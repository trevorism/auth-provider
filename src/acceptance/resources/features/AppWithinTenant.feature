Feature: Adding a new tenant application
  Create a new identity, an application, with a clientId and clientSecret. The application can securely access system resources within its tenant

  Scenario: Register a new application
    Given the auth application is alive
    And the auth test tenant is registered
    And an auth test tenant admin user is registered
    When an app is registered with a clientId
    Then an app is successfully registered with a clientId
    And the app is cleaned up afterwards

  Scenario: A client secret can be associated with an application
    Given the auth application is alive
    And the auth test tenant is registered
    And an auth test tenant admin user is registered
    And an app is registered with a clientId
    When a client secret is requested for the registered app
    Then a client secret is successfully generated for the app
    And the app is cleaned up afterwards

  Scenario: A client secret can be updated
    Given the auth application is alive
    And the auth test tenant is registered
    And an auth test tenant admin user is registered
    And an app is registered with a clientId
    When a client secret is requested to be updated for the registered app
    Then a client secret is successfully updated for the app
    And the app is cleaned up afterwards