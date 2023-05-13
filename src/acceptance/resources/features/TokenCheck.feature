Feature: Valid internal token
  Auth provider uses a token to authorize access to trevorism endpoints.

  Scenario: Internal token is working
    Given the auth application is alive
    When the endpoint tester internal endpoint is invoked
    Then a response of "secure internal" is returned successfully

  Scenario: ClientId and ClientSecret pair are working
    Given the auth application is alive
    When the endpoint tester secure endpoint is invoked
    Then a response of "secure hello json" is returned successfully