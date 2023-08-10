# Sentc sdk changelog

Changes also affect the [server API](https://github.com/sentclose/sentc-api).

# 0.10.0

- 2023/08/11
- Added [Two-factor auth (2fa)](https://sentc.com/guide/e2ee/user.html#multi-factor-authentication)
- Refactored [searchable](https://sentc.com/guide/e2ee/searchable.html) to use it without the api
- [Verify login](https://sentc.com/protocol/#verify-login) (the password) before users receive the keys
- Added [crypto light lib](https://sentc.com/guide/light/) with user and group management