-- Example tailnet policy for the flag stack. Placeholders only.
--
-- group:flag-members   people whose devices may reach the probe and, with a
--                      tsidp rule, get the member claim in their OIDC login
-- tag:flag-probe       the probe node (tcp:443 from members, no Funnel)
-- tag:flag-idp         the tsidp node (Funnel so a public relying party can
--                      reach /token and the JWKS; tsidp itself refuses
--                      /authorize, its admin UI and DCR over Funnel)
--
-- Built on the vendored tailnet-acl types (see vendor/tailnet-acl/PIN.md).
-- This file renders the whole policy; replace the placeholder identities.
let T = ./vendor/tailnet-acl/ACL.dhall

let J = ./vendor/tailnet-acl/JSON.dhall

let G = ./vendor/tailnet-acl/Grant.dhall

let user = { you = "you@example.com", admin = "admin@example.com" }

let group = { members = "group:flag-members" }

let tag = { probe = "tag:flag-probe", idp = "tag:flag-idp" }

let groups
    : List T.Group
    = [ { mapKey = group.members, mapValue = [ user.you ] } ]

-- Admin-only owners: no tagged device can mint these tags next to another.
let tagOwners
    : List T.TagOwner
    = [ { mapKey = tag.probe, mapValue = [ "autogroup:admin" ] }
      , { mapKey = tag.idp, mapValue = [ "autogroup:admin" ] }
      ]

-- Members keep their normal access elsewhere; this example adds no ACL rules.
let acls
    : List T.ACLRule
    = [ { action = "accept", src = [ "autogroup:member" ], dst = [ "autogroup:self:*" ] }
      ]

let grants
    : List G.Grant
    = [ -- Members reach the probe, and Serve forwards the probe capability.
        G.net [ group.members ] [ tag.probe ] [ "tcp:443" ]
      , G.cap
          [ group.members ]
          [ tag.probe ]
          [ G.Cap.Probe { cap = "example.org/cap/flag-probe", flag = "member" } ]
      , -- Members reach tsidp, and tsidp adds the member claim to their login.
        G.net [ group.members ] [ tag.idp ] [ "tcp:443" ]
      , G.cap
          [ group.members ]
          [ tag.idp ]
          [ G.Cap.Tsidp
              (   G.tsidpEmpty
                //  { extraClaims =
                        Some
                          [ { mapKey = "flag_member", mapValue = J.string "true" } ]
                    , includeInUserInfo = Some True
                    }
              )
          ]
      , -- Only the admin sees tsidp's admin UI.
        G.cap
          [ user.admin ]
          [ tag.idp ]
          [ G.Cap.Tsidp (G.tsidpEmpty // { allowAdminUI = Some True }) ]
      ]

let nodeAttrs
    : List T.NodeAttr
    = [ { target = [ tag.idp ], attr = [ "funnel" ] } ]

let autoApprovers
    : T.AutoApprovers
    = { routes = [] : List { mapKey : Text, mapValue : List Text }
      , exitNode = [] : List Text
      , services = [] : List { mapKey : Text, mapValue : List Text }
      }

in  { groups
    , tagOwners
    , acls
    , grants = G.render grants
    , ssh = [] : List T.SSHRule
    , nodeAttrs
    , autoApprovers
    , hosts = [] : List T.Host
    }
