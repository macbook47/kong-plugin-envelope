-- Configuration schema for the "envelope" plugin (spec section 9).
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "envelope",
  fields = {
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {
          { mode = { type = "string", required = true, default = "protect",
                     one_of = { "protect", "handshake" } } },
          { session_ttl = { type = "integer", required = true, default = 900,
                            between = { 60, 86400 } } },
          { clock_skew = { type = "integer", required = true, default = 60,
                           between = { 5, 600 } } },
          { max_seq_per_session = { type = "integer", required = true, default = 100000,
                                    between = { 1, 10000000 } } },
          { max_body_size = { type = "integer", required = true, default = 1048576,
                              between = { 1024, 52428800 } } },
          { require_consumer = { type = "boolean", required = true, default = true } },
          { enveloped_methods = { type = "array", required = true,
                                  default = { "POST", "PUT", "PATCH", "DELETE" },
                                  elements = { type = "string",
                                               one_of = { "POST", "PUT", "PATCH", "DELETE" } } } },
        },
      },
    },
  },
}
