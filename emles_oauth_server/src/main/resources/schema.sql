drop table if exists oauth_client_token;
create table oauth_client_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255)
);
drop table if exists oauth_client_details;
CREATE TABLE oauth_client_details (
  client_id varchar(255) NOT NULL,
  resource_ids varchar(255) DEFAULT NULL,
  client_secret varchar(255) DEFAULT NULL,
  scope varchar(255) DEFAULT NULL,
  authorized_grant_types varchar(255) DEFAULT NULL,
  web_server_redirect_uri varchar(255) DEFAULT NULL,
  authorities varchar(255) DEFAULT NULL,
  access_token_validity integer DEFAULT NULL,
  refresh_token_validity integer DEFAULT NULL,
  additional_information varchar(255) DEFAULT NULL,
  autoapprove varchar(255) DEFAULT NULL
);
drop table if exists oauth_access_token;
create table oauth_access_token (
  token_id VARCHAR(255),
  token BYTEA,
  authentication_id VARCHAR(255),
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication BYTEA,
  refresh_token VARCHAR(255)
);
drop table if exists oauth_refresh_token;
create table oauth_refresh_token(
  token_id VARCHAR(255),
  token BYTEA,
  authentication BYTEA
);
drop table if exists authority;
CREATE TABLE authority (
  id  integer,
  authority varchar(255),
  primary key (id)
);
drop table if exists app_user;

CREATE TABLE app_user (
  id  integer,
  enabled BOOLEAN not null,
  name varchar(255) not null,
  password varchar(255) not null,
  version integer,
  primary key (id)
);
drop table if exists app_user_authorities;
CREATE TABLE app_user_authorities (
  app_user_id bigint not null,
  authorities_id bigint not null
);
drop table if exists oauth_code;
create table oauth_code (
  code VARCHAR(255), authentication BYTEA
);
drop table if exists oauth_approvals;
create table oauth_approvals (
    userId VARCHAR(255),
    clientId VARCHAR(255),
    scope VARCHAR(255),
    status VARCHAR(10),
    expiresAt TIMESTAMP(0),
    lastModifiedAt TIMESTAMP(0)
);
