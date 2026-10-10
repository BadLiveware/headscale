------------------------ MODULE MCServiceAssignment ------------------------
EXTENDS ServiceAssignment
CONSTANTS c1, c2, c3, h1, h2, h3

MCPref2 == [c \in {c1, c2, c3} |-> CASE c = c1 -> <<h1, h2>>
                                     [] c = c2 -> <<h2, h1>>
                                     [] c = c3 -> <<h1, h2>>]

MCPref3 == [c \in {c1, c2} |-> CASE c = c1 -> <<h1, h2, h3>>
                                 [] c = c2 -> <<h3, h1, h2>>]
=============================================================================
