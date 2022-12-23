Feature: Valid internal token
  Auth provider uses a token to authorize access to trevorism endpoints.

  Scenario: Internal token is working
    Given the auth application is alive
    When the endpoint tester internal endpoint is invoked
    Then a response is returned successfully

  Scenario: Obtain a refresh token
    Given the auth application is alive
    When a refresh token is requested
    When the endpoint tester internal endpoint is invoked
    Then a response is returned successfully