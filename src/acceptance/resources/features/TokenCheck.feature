Feature: Valid internal token
  Auth provider uses a token to authorize access to trevorism endpoints.

  Scenario: Token is alive
    Given the auth application is alive
    When the endpoint tester internal endpoint is invoked
    Then a response is returned successfully