package = "kong-plugin-envelope"
version = "0.1.0-1"
source = {
  url = "git+https://github.com/<your-account>/kong-plugin-envelope.git",
  tag = "v0.1.0",
}
description = {
  summary = "Envelope v1: JSON body encryption between clients and Kong Gateway",
  license = "Proprietary",
}
-- lua-resty-openssl is bundled with Kong 3.x, so there are no extra dependencies.
dependencies = {}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.envelope.handler"] = "kong/plugins/envelope/handler.lua",
    ["kong.plugins.envelope.schema"]  = "kong/plugins/envelope/schema.lua",
    ["kong.plugins.envelope.crypto"]  = "kong/plugins/envelope/crypto.lua",
  },
}
