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

// fetchBackoff tracks the unanswered fetches of one node.
type fetchBackoff struct {
	hash     string
	failures int
	retryAt  time.Time
}

// servicesFetcher keeps the advertised services that Headscale holds for a
// node in step with the [tailcfg.Hostinfo.ServicesHash] the node reports. A
// client only sends that hash; when it differs from the hash of the stored
// list, the fetcher asks the node for the list with a c2n request.
type servicesFetcher struct {
	h *Headscale

	mu      sync.Mutex
	byID    map[string]*servicesFetch
	pending map[types.NodeID]string
	backoff map[types.NodeID]*fetchBackoff
}

func newServicesFetcher(h *Headscale) *servicesFetcher {
	return &servicesFetcher{
		h:       h,
		byID:    make(map[string]*servicesFetch),
		pending: make(map[types.NodeID]string),
		backoff: make(map[types.NodeID]*fetchBackoff),
	}
}

// syncAll runs [servicesFetcher.sync] for every node. A policy reload calls
// it, because a policy that gains hostnameClaims rules makes the services
// of connected nodes matter, and no map request may come from them soon.
func (f *servicesFetcher) syncAll() {
	for _, node := range f.h.state.ListNodes().All() {
		f.sync(node.ID())
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

	if want == node.AdvertisedServicesHash() {
		return
	}

	if want == "" {
		c, err := f.h.state.SetNodeAdvertisedServices(nodeID, "", nil)
		if err != nil {
			log.Debug().Err(err).Uint64(zf.NodeID, nodeID.Uint64()).Msg("clearing advertised services")
		}

		if !c.IsEmpty() {
			f.h.Change(c)
		}

		return
	}

	// Without a hostnameClaims rule the services cannot matter; a policy
	// reload runs syncAll when that changes.
	if !f.h.state.HostnameClaimsConfigured() {
		return
	}

	if f.h.mapBatcher == nil || !f.h.mapBatcher.IsConnected(nodeID) {
		return
	}

	f.mu.Lock()

	if b, ok := f.backoff[nodeID]; ok {
		switch {
		case b.hash != want:
			delete(f.backoff, nodeID)
		case time.Now().Before(b.retryAt):
			f.mu.Unlock()

			return
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

// lookup returns the pending fetch with the given ID.
func (f *servicesFetcher) lookup(id string) (*servicesFetch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fetch, ok := f.byID[id]

	return fetch, ok
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

// expire drops an unanswered fetch and schedules another: a fetch can be
// lost when the node reconnects, or when another ping to the node is merged
// into the same map response. The wait doubles for each unanswered fetch of
// the same hash, up to servicesRetryMax, so a node that never answers costs
// little.
func (f *servicesFetcher) expire(id string) {
	fetch, ok := f.take(id)
	if !ok {
		return
	}

	f.mu.Lock()

	b, ok := f.backoff[fetch.nodeID]
	if !ok || b.hash != fetch.hash {
		b = &fetchBackoff{hash: fetch.hash}
		f.backoff[fetch.nodeID] = b
	}

	delay := retryDelay(b.failures)
	b.failures++
	b.retryAt = time.Now().Add(delay)

	f.mu.Unlock()

	log.Debug().
		Uint64(zf.NodeID, fetch.nodeID.Uint64()).
		Dur("retry_in", delay).
		Msg("c2n services fetch timed out")

	time.AfterFunc(delay, func() { f.sync(fetch.nodeID) })
}

// retryDelay is the wait before the next fetch after failures earlier
// unanswered fetches: servicesFetchTimeout doubled per failure, capped.
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

// complete stores the services from a node's c2n response.
func (f *servicesFetcher) complete(id string, machineKey key.MachinePublic, body *bufio.Reader) error {
	pending, ok := f.lookup(id)
	if !ok {
		return errUnknownC2NRequest
	}

	// Check the sender before taking the fetch, so a post from another
	// machine cannot cancel it.
	node, ok := f.h.state.GetNodeByID(pending.nodeID)
	if !ok || node.MachineKey() != machineKey {
		return errC2NWrongMachine
	}

	fetch, ok := f.take(id)
	if !ok {
		return errUnknownC2NRequest
	}

	f.mu.Lock()
	delete(f.backoff, fetch.nodeID)
	f.mu.Unlock()

	resp, err := http.ReadResponse(body, nil)
	if err != nil {
		return fmt.Errorf("reading c2n response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", errC2NStatus, resp.StatusCode)
	}

	var res tailcfg.C2NVIPServicesResponse

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return fmt.Errorf("decoding c2n vip-services response: %w", err)
	}

	var active []string

	for _, svc := range res.VIPServices {
		if svc == nil || !svc.Active || svc.Name.Validate() != nil {
			continue
		}

		active = append(active, svc.Name.String())
	}

	// Store the list under the Hostinfo hash the fetch was made for, not
	// the hash in the response: when the two disagree, comparing against
	// the response hash would refetch at once, and forever.
	c, err := f.h.state.SetNodeAdvertisedServices(fetch.nodeID, fetch.hash, active)
	if err != nil {
		return err
	}

	log.Debug().
		Uint64(zf.NodeID, fetch.nodeID.Uint64()).
		Strs("services", active).
		Msg("stored advertised services from c2n")

	if !c.IsEmpty() {
		f.h.Change(c)
	}

	// The node may have changed its services again while this fetch was
	// in flight.
	f.sync(fetch.nodeID)

	return nil
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
