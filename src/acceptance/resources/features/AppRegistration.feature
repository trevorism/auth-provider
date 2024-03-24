Feature: Adding a new application
  Create a new identity, an application, with a clientId and clientSecret. The application can securely access system resources.

  Scenario: Register a new application
    Given the auth application is alive
    When an app is registered with a clientId
    Then an app is succesfully registered with a clientId
    And the app is cleaned up afterwards

  Scenario: A client secret can be associated with an application
    Given the auth application is alive
    And an app is registered with a clientId
    When a client secret is requested for the registered app
    Then a client secret is successfully generated for the app
    And the app is cleaned up afterwards

  Scenario: A client secret can be updated
    Given the auth application is alive
    And an app is registered with a clientId
    When a client secret is requested to be updated for the registered app
    Then a client secret is successfully updated for the app
    And the app is cleaned up afterwards

  Scenario: Applications on Trevorism can be listed
    Given the auth application is alive
    When the a list of apps is requested
    Then the app list is successfully returned