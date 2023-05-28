
The Redis third-party authentication module has the following issues due to the fact that open-source Redis authentication reads authentication information from files:

- From a security perspective, saving passwords in configuration files is not secure and cannot meet enterprise level security requirements.
- When in cluster mode, the permission information in each instance is separate and it is not easy to maintain consistency.


# Roadmap

- [ ] Support synchronizing user permission information from the postgreSQL database.
- [ ] Support synchronizing permission information from HTTP requests.


# Link

- [Redis](https://github.com/redis/redis): Redis is an in-memory database that persists on disk. 
- [libpqxx](https://github.com/jtv/libpqxx): The C++ API to the PostgreSQL database management system.