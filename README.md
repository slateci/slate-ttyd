For an overview of the overall sandbox setup, [see here](https://github.com/slateci/sandbox-portal).

# SLATE ttyd

The ttyd application allows one to access to a terminal windows through http. It is a fork of [ttyd](https://github.com/tsl0922/ttyd/) to accomodate the security requirements. The README of the original project is [here](TTYD-README.md).

# Checkmk monitoring

Check_mk is setup to monitor a particular instance of ttyd as it is running in production within the sandbox's kubernetes cluster. The test only checks whether ttyd responds, without simulating an actual session.
