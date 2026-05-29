# threatscope

<img alt="ThreatScope Logo" src="/webapp/assets/img/logo-home.jpg" width="200px" align="center"/>

Interface to query multiple OSINT sources and internal data sources when researching IOC or IOAs. Currently IPv4, Domains, Emails, and Hashes are supported against public OSINT sources as well as internal MISP and ElasticSearch databases.

## Installation
- Copy all files to your server and configure the required settings in webapp/config.php
- Use docker-compose.yml to setup environment.  Currently is setup in an insecure method.  Recommend putting it behind a reverse proxy or installing your own certificates.
- Start and build the docker container 'docker compose up -d --build'
> All files are copied to the container on build, so modifications to the files in webapp will not be active until the next docker build.
