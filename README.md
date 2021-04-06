For an overview of the overall sandbox setup, [see here](https://github.com/slateci/sandbox-portal).

# SLATE ttyd

The ttyd application allows one to access to a terminal windows through http. It is a fork of [ttyd](https://github.com/tsl0922/ttyd/) to accomodate the security requirements. The README of the original project is [here](TTYD-README.md).

# Checkmk monitoring

Check_mk is setup to monitor a particular instance of ttyd as it is running in production within the sandbox's kubernetes cluster. The test only checks whether ttyd responds, without simulating an actual session.

# Updating

TTYD must occasionally be updated by synchronizing with the upstream [code](https://github.com/tsl0922/ttyd). Typically syncrhonizing the Javascript package versions found in https://github.com/tsl0922/ttyd/blob/main/html/package.json is sufficient. 

Occasionally, the updates packages introduce breaking changes into the TTYD component, and the underlying code must also be updated. The best way to do this is to copy the upstream repository, then re-add the customizations needed for SLATE described below.

Forcing a rebuild of the [container](https://github.com/slateci/container-ttyd), and restarting the [sandbox-portal](https://github.com/slateci/sandbox-portal) will push the updates live.

## Customizations for SLATE

Don't compress the HTML output, as we need to inject some code into it
https://github.com/slateci/slate-ttyd/commit/9b9ab30f3513cbd2ec6a5417874f1010f9862c78
https://github.com/slateci/slate-ttyd/commit/f2e1969945c351c53991b6e6e6e33c25af2dae6b

Add and utilize the auth scheme for SLATE in the server
https://github.com/slateci/slate-ttyd/commit/2a83388aac13d18d5571fd93add0f29c72846e01
https://github.com/slateci/slate-ttyd/commit/780ec6c19e638fb46aa60fd5ccdab982c562404a
https://github.com/slateci/slate-ttyd/commit/217c364969d359c05d7f8cb0d20d3088dd5a48e9

Remove old or unused files according to updates in the CMakeLists.txt
