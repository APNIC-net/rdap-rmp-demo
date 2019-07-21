## rdap-rmp

A proof-of-concept for RDAP mirroring.  See
[https://tools.ietf.org/html/draft-harrison-regext-rdap-mirroring-00](https://tools.ietf.org/html/draft-harrison-regext-rdap-mirroring-00).

### Build

    $ docker build -t apnic/rdap-rmp .

### Example usage

    $ docker run -it apnic/rdap-rmp /bin/bash

Set up test state for the mirroring server and client.  The mirroring
client also acts as an RDAP server, so that the objects retrieved via
mirroring can be accessed by standard RDAP clients.

    # rdap-rmp-test-setup
    Generated keypair for servers...
    Finished setting up server state...
    Server is running on port 8080...
    Finished setting up client state...
    Client is running on port 8081...
    Finished test setup.

Add some objects to the server's object directory.

    # cat /eg/test-entity
    { "rdapConformance": [ "rdap_level_0" ],
      "objectClassName": "entity",
      "handle": "TEST-ENTITY",
      "links": [ { "rel": "self",
                   "href": "https://example.com/entity/TEST-ENTITY" } ] }
    # cp /eg/test-entity /rdap/server/objects/
    # cat /eg/other-entity
    { "rdapConformance": [ "rdap_level_0" ],
      "objectClassName": "entity",
      "handle": "OTHER-ENTITY",
      "links": [ { "rel": "self",
                   "href": "https://example.com/entity/OTHER-ENTITY" },
                 { "rel": "related",
                   "href": "https://example.com/entity/TEST-ENTITY" } ] }
    # cp /eg/other-entity /rdap/server/objects/
    # cat /eg/ip-network-10-8
    { "rdapConformance": [ "rdap_level_0" ],
      "objectClassName": "ip network",
      "handle": "RFC 1918 network",
      "ipVersion": "v4",
      "startAddress": "10.0.0.0",
      "endAddress": "10.255.255.255",
      "links": [ { "rel": "self",
                   "href": "https://example.com/ip/10.0.0.0/8" } ] }
    # cp /eg/ip-network-10-8 /rdap/server/objects/

Generate the initial snapshot and update notification file for the
server.

    # curl -i -X POST http://localhost:8080/snapshot/generate
    HTTP/1.1 200 OK
    ...
    # curl -i -X POST http://localhost:8080/unf/generate
    HTTP/1.1 200 OK
    ...

Refresh the client.

    # curl -i -X POST http://localhost:8081/refresh
    HTTP/1.1 200 OK
    ...

Confirm that the objects can be retrieved from the client.

    # curl -s http://localhost:8081/entity/TEST-ENTITY | jq .
    {
      "objectClassName": "entity",
      "rdapConformance": [
        "rdap_level_0"
      ],
      "handle": "TEST-ENTITY",
      "links": [
        {
          "href": "http://localhost:8081/entity/TEST-ENTITY",
          "rel": "self"
        }
      ]
    }
    # curl -s http://localhost:8081/entity/OTHER-ENTITY | jq .
    {
      "objectClassName": "entity",
      "rdapConformance": [
        "rdap_level_0"
      ],
      "handle": "OTHER-ENTITY",
      "links": [
        {
          "href": "http://localhost:8081/entity/OTHER-ENTITY",
          "rel": "self"
        },
        {
          "rel": "related",
          "href": "http://localhost:8081/entity/TEST-ENTITY"
        }
      ]
    }
    # curl -s http://localhost:8081/ip/10.2.3.4 | jq .
    {
      "objectClassName": "ip network",
      "rdapConformance": [
        "rdap_level_0"
      ],
      "handle": "RFC 1918 network",
      "startAddress": "10.0.0.0",
      "endAddress": "10.255.255.255",
      "ipVersion": "v4",
      "links": [
        {
          "rel": "self",
          "href": "http://localhost:8081/ip/10.0.0.0/8"
        }
      ]
    }

Update/remove the objects, generate a delta file, and generate a new
update notification file.

    # sed -i 's/RFC 1918 network/Private network/' /rdap/server/objects/ip-network-10-8
    # rm /rdap/server/objects/other-entity
    # curl -i -X POST http://localhost:8080/delta/generate
    HTTP/1.1 200 OK
    ...
    # curl -i -X POST http://localhost:8080/unf/generate
    HTTP/1.1 200 OK
    ...

Refresh the client.

    # curl -i -X POST http://localhost:8081/refresh
    HTTP/1.1 200 OK
    ...

Confirm that the changes are visible.

    # curl -s http://localhost:8081/ip/10.2.3.4 | jq .
    {
      "objectClassName": "ip network",
      "rdapConformance": [
        "rdap_level_0"
      ],
      "handle": "Private network",
      "startAddress": "10.0.0.0",
      "endAddress": "10.255.255.255",
      "ipVersion": "v4",
      "links": [
        {
          "rel": "self",
          "href": "http://localhost:8081/ip/10.0.0.0/8"
        }
      ]
    }
    # curl -s http://localhost:8081/entity/other-entity
    HTTP/1.1 404 Not Found
    ...

See `/rdap/server/server-log` and `/rdap/client/client-log` for
more detailed information about what each process is doing.

### Todo

   - Out-of-band snapshot application in client.
   - Snapshot consolidation in server.
   - RDAP search endpoints in client.

### License

See [LICENSE](./LICENSE).
