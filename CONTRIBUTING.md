# Contribution Guidelines

## Merge Requests
All merge requests must include a description. The description should at a minimum, provide background on the purpose of the merge request. Consider providing an overview of why the work is taking place; don’t assume familiarity with the history. If the merge request is related to an issue, make sure to mention the issue number(s).
Each merge requests should address a single fix. Please do not fix or implement several issues or features in a single merge unless there is a clear and logical reason to do so. This allows for easier release control and testing.
Provide details of any testing performed. Test proposed changes to ensure they work and do also work with any dependencies. Details of this testing should be included, if possible, within the description. Automated testing will be carried out on PR creation.
All commits must come through merge requests.
Commits should include all relevant documentation updates. If your proposed changes introduced new configuration variables or equivalent, please include the related documentation updates in the merge request.
Include an updated CHANGELOG.md entry. Please include in your commit and update to the CHANGELOG.md following the pattern seen. If this will be a new release, please leave the date as Unreleased as the merge may not happen for a number of days after the initial merge request.
## Code Review
Merge requests will not be merged until they've been code reviewed by at least one owner. You should implement any code review feedback unless you strongly object to it. In the event that you object to the code review feedback, you should make your case clearly and calmly. This can be done best with a quick meeting or voice call to avoid misunderstanding - this is a collaborative effort so it is good to talk. Once all reviews have passed the code can be merged.

Review will be by 2 engineers. @iainthegray will be one.
Please select one or more reviewer(s) from this list:

* Dan Brown @roooms
* Johnny Carlin @thejohnny
* Sean Carolan @scarolan
* Nicolas Corraello @ncorrare
* Jeremiah Jenkins @jjenkins70
* Andrew Klaas @Andrew-Klaas
* Nathan Lacey @nathanl79
* Brian Shumate @brianshumate

## Linting and Formatting
Please ensure your code is linted and formatted to appropriate standards.

* Python: Please use pylama to audit your code.
* Terraform: Please ensure terraform fmt has been run across the code base.
* GoLang: Please ensure the code passes golint, go fmt and go vet.
* Bash:
  * Use the google shell style guidehttps://google.github.io/styleguide/shell.xml
  * shellcheck is very useful for checking shell scripts for weirdness.
https://github.com/koalaman/shellcheck
