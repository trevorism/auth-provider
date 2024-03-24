Feature: Administering Applications
  An application can be listed and retrieved by an application identity

  Scenario: Applications on Trevorism can be listed
    Given the auth application is alive
    When the a list of apps is requested
    Then the app list is successfully returned