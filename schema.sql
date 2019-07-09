CREATE TABLE IF NOT EXISTS user (
  username    VARCHAR(32)   PRIMARY KEY,
  password    CHAR(60)      NOT NULL,
  admin       INT           DEFAULT 0,
  locked      INT           DEFAULT 0,
  last_login  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  registration TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api (
  id          CHAR(36)      PRIMARY KEY,
  name        VARCHAR(64)   NOT NULL,
  contact     VARCHAR(128),
  artifactID  VARCHAR(64),
  groupID     VARCHAR(64),
  version     VARCHAR(8)    NOT NULL,
  size        INT,
  description TEXT,
  term        CHAR(1)       NOT NULL,
  year        INT           NOT NULL,
  team        CHAR(1)       NOT NULL,
  lastupdate  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  creator     VARCHAR(32),
  image_url   VARCHAR(48),
  CONSTRAINT FOREIGN KEY creator_ref(creator) REFERENCES user(username) ON UPDATE CASCADE ON DELETE SET NULL,
  CONSTRAINT uniq_artifact UNIQUE(artifactID, groupID)
);

CREATE TABLE IF NOT EXISTS version (
  apiId       CHAR(36)      NOT NULL,
  vnumber     VARCHAR(16)   NOT NULL,
  info        TEXT,
  CONSTRAINT FOREIGN KEY idref(apiId) REFERENCES api(id) ON DELETE CASCADE,
  CONSTRAINT uniq_version UNIQUE(apiId, vnumber)
);

