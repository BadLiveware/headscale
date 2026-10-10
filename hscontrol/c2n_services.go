package hscontrol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/rands"
)

const (
	// c2nResponsePath is the Noise endpoint a node posts a c2n
	// (control-to-node) response to. Tailscale clients always answer a
	// c2n PingRequest over Noise, whatever the URL scheme and host.
	c2nResponsePath = "/machine/c2n-response"

	// c2nPingType marks a [tailcfg.PingRequest] as a c2n HTTP request.
	c2nPingType = "c2n"

	// c2nVIPServicesRequest asks a node for the services it advertises.
	// The client answers with a [tailcfg.C2NVIPServicesResponse].
	c2nVIPServicesRequest = "GET /vip-services HTTP/1.1\r\nHost: headscale\r\n\r\n"

	// servicesFetchTimeout is how long a fetch may stay unanswered before
	// it counts as failed.
	servicesFetchTimeout = 10 * time.Second

	// servicesRetryMax caps the wait between fetches to a node that does
	// not answer. The wait doubles from servicesFetchTimeout.
	servicesRetryMax = 5 * time.Minute

	servicesFetchIDLength = 16
)

var (
	errUnknownC2NRequest = errors.New("unknown or expired c2n request")
	errC2NWrongMachine   = errors.New("c2n response from a machine that was not asked")
	errC2NStatus         = errors.New("c2n request failed on the node")
)

type servicesFetch struct {
	nodeID types.NodeID
	hash   string
	timer  *time.Timer
}

// fetchBackoff tracks the failed fetches of one node for one hash.
type fetchBackoff struct {
	hash     string
	failures int
	retryAt  time.Time
	retry    *time.Timer
}

// servicesFetcher keeps the advertised services that Headscale holds for a
// node in step with the [tailcfg.Hostinfo.ServicesHash] the node reports. A
// client only sends that hash; when it differs from the hash of the stored
// list, the fetcher asks the node for the list with a c2n request.
//
// Rules, which hold for every node:
//   - At most one fetch is pending, for the node's current hash; a new hash
//     or an empty hash cancels it.
//   - A fetch ID is used once, and only an answer over the Noise session of
//     the node that was asked counts.
//   - An answer is stored only while its hash is still the node's current
//     hash ([state.State.SetNodeAdvertisedServices] checks it atomically).
//   - A failed fetch (no answer in time, or a bad answer) is retried with a
//     doubling wait, and the old list stops claiming
//     ([state.State.WithdrawStaleAdvertisedServices]), so a node that may
//     have withdrawn a service does not keep it for long.
type servicesFetcher struct {
	h *Headscale

	mu      sync.Mutex
	closed  bool
	byID    map[string]*servicesFetch
	pending map[types.NodeID]string
	backoff map[types.NodeID]*fetchBackoff

	// syncAll runs one pass at a time; a request during a pass makes the
	// pass run once more.
	syncAllRunning bool
	syncAllAgain   bool
}

func newServicesFetcher(h *Headscale) *servicesFetcher {
	return &servicesFetcher{
		h:       h,
		byID:    make(map[string]*servicesFetch),
		pending: make(map[types.NodeID]string),
		backoff: make(map[types.NodeID]*fetchBackoff),
	}
}

// stop cancels every pending fetch and retry; later calls do nothing.
func (f *servicesFetcher) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed = true

	for id, fetch := range f.byID {
		fetch.timer.Stop()
		delete(f.byID, id)
	}

	for nodeID, b := range f.backoff {
		if b.retry != nil {
			b.retry.Stop()
		}

		delete(f.backoff, nodeID)
	}

	clear(f.pending)
}

// syncAll runs [servicesFetcher.sync] for every node. A policy reload calls
// it, because a policy that gains hostnameClaims rules makes the services
// of connected nodes matter, and no map request may come from them soon.
// Overlapping calls share one pass, which runs once more if asked during it.
func (f *servicesFetcher) syncAll() {
	f.mu.Lock()
	if f.syncAllRunning {
		f.syncAllAgain = true
		f.mu.Unlock()

		return
	}

	f.syncAllRunning = true
	f.mu.Unlock()

	for {
		for _, node := range f.h.state.ListNodes().All() {
			f.sync(node.ID())
		}

		f.mu.Lock()
		if !f.syncAllAgain || f.closed {
			f.syncAllRunning = false
			f.syncAllAgain = false
			f.mu.Unlock()

			return
		}

		f.syncAllAgain = false
		f.mu.Unlock()
	}
}

// cancelLocked drops the pending fetch and the backoff of a node.
func (f *servicesFetcher) cancelLocked(nodeID types.NodeID) {
	if id, ok := f.pending[nodeID]; ok {
		f.byID[id].timer.Stop()
		delete(f.byID, id)
		delete(f.pending, nodeID)
	}

	if b, ok := f.backoff[nodeID]; ok {
		if b.retry != nil {
			b.retry.Stop()
		}

		delete(f.backoff, nodeID)
	}
}

// sync compares the services hash in the node's Hostinfo with the hash of
// its stored services and starts a fetch when they differ. A client that
// advertises nothing reports an empty hash, which clears the stored list
// without a fetch.
func (f *servicesFetcher) sync(nodeID types.NodeID) {
	node, ok := f.h.state.GetNodeByID(nodeID)
	if !ok {
		return
	}

	var want string
	if node.Hostinfo().Valid() {
		want = node.Hostinfo().ServicesHash()
	}

	f.mu.Lock()

	if f.closed {
		f.mu.Unlock()

		return
	}

	if want == node.AdvertisedServicesHash() || want == "" {
		// Nothing to fetch: the list is current, or the node advertises
		// nothing. A fetch for an older hash must not land afterwards.
		f.cancelLocked(nodeID)
		f.mu.Unlock()

		if want == "" && node.AdvertisedServicesHash() != "" {
			f.store(nodeID, "", nil)
		}

		return
	}

	// Without a hostnameClaims rule the services cannot matter; a policy
	// reload runs syncAll when that changes.
	if !f.h.state.HostnameClaimsConfigured() || f.h.mapBatcher == nil || !f.h.mapBatcher.IsConnected(nodeID) {
		f.mu.Unlock()

		return
	}

	if b, ok := f.backoff[nodeID]; ok {
		if b.hash == want && time.Now().Before(b.retryAt) {
			f.mu.Unlock()

			return
		}

		if b.hash != want {
			if b.retry != nil {
				b.retry.Stop()
			}

			delete(f.backoff, nodeID)
		}
	}

	if id, ok := f.pending[nodeID]; ok {
		if f.byID[id].hash == want {
			f.mu.Unlock()

			return
		}

		f.byID[id].timer.Stop()
		delete(f.byID, id)
	}

	id := rands.HexString(servicesFetchIDLength)
	fetch := &servicesFetch{nodeID: nodeID, hash: want}
	fetch.timer = time.AfterFunc(servicesFetchTimeout, func() { f.expire(id) })
	f.byID[id] = fetch
	f.pending[nodeID] = id

	f.mu.Unlock()

	log.Debug().
		Uint64(zf.NodeID, nodeID.Uint64()).
		Str("services.hash", want).
		Msg("fetching advertised services over c2n")

	f.h.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL:     f.callbackURL(id),
		Types:   c2nPingType,
		Payload: []byte(c2nVIPServicesRequest),
		// Tailscale clients always answer c2n over Noise; say so anyway.
		URLIsNoise: true,
	}))
}

// store applies a list for hash and dispatches the resulting DNS change.
// A list for a hash the node has moved past is dropped.
func (f *servicesFetcher) store(nodeID types.NodeID, hash string, services []string) {
	c, err := f.h.state.SetNodeAdvertisedServices(nodeID, hash, services)

	switch {
	case errors.Is(err, state.ErrServicesHashMoved):
		log.Debug().Uint64(zf.NodeID, nodeID.Uint64()).Msg("dropping advertised services for an older services hash")
	case err != nil:
		log.Debug().Err(err).Uint64(zf.NodeID, nodeID.Uint64()).Msg("storing advertised services")
	case !c.IsEmpty():
		f.h.Change(c)
	}
}

// callbackURL returns the URL the node posts its c2n response to. The
// client sends it over Noise, so only the path and query reach Headscale.
func (f *servicesFetcher) callbackURL(id string) string {
	host := "headscale"

	u, err := url.Parse(f.h.cfg.ServerURL)
	if err == nil && u.Host != "" {
		host = u.Host
	}

	return "https://" + host + c2nResponsePath + "?id=" + id
}

// takeFrom removes and returns the fetch with the given ID when machineKey
// is the key of the node it was sent to. The check and the removal happen
// under one lock, so a timeout cannot slip between them and reject an
// answer that arrived in time, and a post from another machine cannot
// consume the fetch.
func (f *servicesFetcher) takeFrom(id string, machineKey key.MachinePublic) (*servicesFetch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fetch, ok := f.byID[id]
	if !ok {
		return nil, errUnknownC2NRequest
	}

	node, ok := f.h.state.GetNodeByID(fetch.nodeID)
	if !ok || node.MachineKey() != machineKey {
		return nil, errC2NWrongMachine
	}

	fetch.timer.Stop()
	delete(f.byID, id)

	if f.pending[fetch.nodeID] == id {
		delete(f.pending, fetch.nodeID)
	}

	return fetch, nil
}

// take removes and returns the fetch with the given ID.
func (f *servicesFetcher) take(id string) (*servicesFetch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fetch, ok := f.byID[id]
	if !ok {
		return nil, false
	}

	fetch.timer.Stop()
	delete(f.byID, id)

	if f.pending[fetch.nodeID] == id {
		delete(f.pending, fetch.nodeID)
	}

	return fetch, true
}

// expire handles a fetch that got no answer in time. A fetch can be lost
// when the node reconnects, or when another ping to the node is merged into
// the same map response.
func (f *servicesFetcher) expire(id string) {
	fetch, ok := f.take(id)
	if !ok {
		return
	}

	f.failed(fetch, "no answer")
}

// failed schedules the next fetch for the node after a doubling wait, up
// to servicesRetryMax, so a node that never answers costs little, and stops
// the node's older list from claiming while the current one is unknown.
func (f *servicesFetcher) failed(fetch *servicesFetch, reason string) {
	f.mu.Lock()

	if f.closed {
		f.mu.Unlock()

		return
	}

	b, ok := f.backoff[fetch.nodeID]
	if !ok || b.hash != fetch.hash {
		if ok && b.retry != nil {
			b.retry.Stop()
		}

		b = &fetchBackoff{hash: fetch.hash}
		f.backoff[fetch.nodeID] = b
	}

	delay := retryDelay(b.failures)
	b.failures++
	b.retryAt = time.Now().Add(delay)

	if b.retry != nil {
		b.retry.Stop()
	}

	b.retry = time.AfterFunc(delay, func() { f.sync(fetch.nodeID) })

	f.mu.Unlock()

	log.Debug().
		Uint64(zf.NodeID, fetch.nodeID.Uint64()).
		Str("reason", reason).
		Dur("retry_in", delay).
		Msg("c2n services fetch failed")

	c, err := f.h.state.WithdrawStaleAdvertisedServices(fetch.nodeID)
	if err == nil && !c.IsEmpty() {
		f.h.Change(c)
	}
}

// retryDelay is the wait before the next fetch after failures earlier
// failed fetches: servicesFetchTimeout doubled per failure, capped.
func retryDelay(failures int) time.Duration {
	delay := servicesFetchTimeout
	for range failures {
		delay *= 2
		if delay >= servicesRetryMax {
			return servicesRetryMax
		}
	}

	return delay
}

// complete handles a node's c2n response for the fetch with the given ID.
func (f *servicesFetcher) complete(id string, machineKey key.MachinePublic, body *bufio.Reader) error {
	fetch, err := f.takeFrom(id, machineKey)
	if err != nil {
		return err
	}

	active, err := parseVIPServicesResponse(body)
	if err != nil {
		f.failed(fetch, err.Error())

		return err
	}

	f.mu.Lock()
	if b, ok := f.backoff[fetch.nodeID]; ok && b.hash == fetch.hash {
		if b.retry != nil {
			b.retry.Stop()
		}

		delete(f.backoff, fetch.nodeID)
	}
	f.mu.Unlock()

	// Store the list under the Hostinfo hash the fetch was made for, not
	// the hash in the response: when the two disagree, comparing against
	// the response hash would refetch at once, and forever.
	f.store(fetch.nodeID, fetch.hash, active)

	log.Debug().
		Uint64(zf.NodeID, fetch.nodeID.Uint64()).
		Strs("services", active).
		Msg("received advertised services over c2n")

	// The node may have changed its services again while this fetch was
	// in flight.
	f.sync(fetch.nodeID)

	return nil
}

// parseVIPServicesResponse reads the serialised HTTP response of a node to
// GET /vip-services and returns the names of its active services.
func parseVIPServicesResponse(body *bufio.Reader) ([]string, error) {
	resp, err := http.ReadResponse(body, nil)
	if err != nil {
		return nil, fmt.Errorf("reading c2n response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errC2NStatus, resp.StatusCode)
	}

	var res tailcfg.C2NVIPServicesResponse

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, fmt.Errorf("decoding c2n vip-services response: %w", err)
	}

	var active []string

	for _, svc := range res.VIPServices {
		if svc == nil || !svc.Active || svc.Name.Validate() != nil {
			continue
		}

		active = append(active, svc.Name.String())
	}

	return active, nil
}

// C2NResponseHandler receives a node's answer to a c2n [tailcfg.PingRequest]:
// the node's HTTP response, serialised, as the request body.
func (ns *noiseServer) C2NResponseHandler(writer http.ResponseWriter, req *http.Request) {
	err := ns.headscale.servicesFetcher.complete(
		req.URL.Query().Get("id"),
		ns.machineKey,
		bufio.NewReader(req.Body),
	)

	switch {
	case errors.Is(err, errUnknownC2NRequest):
		http.Error(writer, err.Error(), http.StatusNotFound)
	case errors.Is(err, errC2NWrongMachine):
		http.Error(writer, err.Error(), http.StatusForbidden)
	case err != nil:
		log.Warn().Err(err).Str("machine.key", ns.machineKey.ShortString()).Msg("handling c2n response")
		http.Error(writer, err.Error(), http.StatusBadRequest)
	default:
		writer.WriteHeader(http.StatusOK)
	}
}
