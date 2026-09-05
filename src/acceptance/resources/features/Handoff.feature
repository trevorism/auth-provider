Feature: Handing off a login to another host
  A caller with a valid token can mint a one-time code bound to an allowed redirect URI,
  and the receiving app can redeem it exactly once.

  Scenario: A handoff code is redeemed once
    Given the auth application is alive
    When a handoff code is requested for "https://certs.project.trevorism.com/api/auth/callback"
    Then a handoff code is returned
    When the handoff code is redeemed at "https://certs.project.trevorism.com/api/auth/callback"
    Then the caller's access token is returned
    When the handoff code is redeemed at "https://certs.project.trevorism.com/api/auth/callback"
    Then the handoff redeem is rejected

  Scenario: A handoff code cannot be redeemed at a different redirect URI
    Given the auth application is alive
    When a handoff code is requested for "https://certs.project.trevorism.com/api/auth/callback"
    Then a handoff code is returned
    When the handoff code is redeemed at "https://evil.example.org/api/auth/callback"
    Then the handoff redeem is rejected

  Scenario: A handoff code is refused for a redirect URI outside the allowlist
    Given the auth application is alive
    When a handoff code is requested for "https://evil.example.org/api/auth/callback"
    Then the handoff request is rejected

  Scenario: Redirect URIs can be checked against the allowlist
    Given the auth application is alive
    Then the redirect URI "http://localhost:5173/api/auth/callback" is allowed
    And the redirect URI "https://pr-7-dot-certs-dot-trevorism-project.uc.r.appspot.com/api/auth/callback" is allowed
    And the redirect URI "https://evil.appspot.com/api/auth/callback" is not allowed
