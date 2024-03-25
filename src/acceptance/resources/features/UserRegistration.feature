Feature: Administering Users
  Users can be administered on the Trevorism platform

  Scenario: Users on Trevorism can be listed
    Given the auth application is alive
    When the a list of users is requested
    Then the user list is successfully returned