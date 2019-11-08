CREATE SCHEMA `Authorization` ;

CREATE TABLE `Authorization`.`role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) NOT NULL,
  `createdBy` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT NULL,
  `modifiedBy` int(11) DEFAULT NULL,
  `modifiedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `role_name` (`name`)
);

CREATE TABLE `Authorization`.`role_assignment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role_id` int(11) NOT NULL,
  `subject_id` int(11) NOT NULL,
  `subject_type`	int NULL DEFAULT '1',
  `createdBy` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT NULL,
  `modifiedBy` int(11) DEFAULT NULL,
  `modifiedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `role_subject_id_type` (`role_id`,`subject_id`,`subject_type`),
  KEY `subject_id_idx` (`subject_id`),
  KEY `role_id_idx` (`role_id`),
  CONSTRAINT `role_id` FOREIGN KEY (`role_id`) REFERENCES `Authorization`.`role` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
);

CREATE TABLE `Authorization`.`permission_policy` (
  `id` varchar(80) NOT NULL,
  `subjectId` varchar(100) NOT NULL,
  `subjectType` varchar(40) NOT NULL,
  `resource` varchar(40) NOT NULL,
  `createdBy` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT NULL,
  `modifiedBy` int(11) DEFAULT NULL,
  `modifiedAt` datetime DEFAULT NULL,
  `policy` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `perm_policy_subject_resource_unique` (`subjectId`,`subjectType`,`resource`),
  KEY `subject_key` (`subjectId`)
);

CREATE TABLE `Authorization`.`client` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `redirect_uri` varchar(8192),
  `secret` varchar(255),
  `createdBy` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT NULL,
  `modifiedBy` int(11) DEFAULT NULL,
  `modifiedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_id` (`client_id`)
);

CREATE TABLE `Authorization`.`client_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `scope` varchar(8192),
  `createdBy` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT NULL,
  `modifiedBy` int(11) DEFAULT NULL,
  `modifiedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_user_id` (`client_id`,`user_id`),
  KEY `client_id_idx` (`client_id`),
  KEY `user_id_idx` (`user_id`),
  CONSTRAINT `client_id` FOREIGN KEY (`client_id`) REFERENCES `Authorization`.`client` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
);

CREATE TABLE `Authorization`.`group`  (
	`id`         	int(11) AUTO_INCREMENT NOT NULL,
	`name`       	varchar(150) NOT NULL,
	`description`	varchar(2048) NULL,
	`private_group`	boolean NOT NULL DEFAULT TRUE,
	`self_register`	boolean NOT NULL DEFAULT FALSE,
	`createdBy`  	int(11) NULL,
	`createdAt`  	datetime(0) NULL,
	`modifiedBy` 	int(11) NULL,
	`modifiedAt` 	datetime(0) NULL,
	PRIMARY KEY(`id`)
);

CREATE TABLE `Authorization`.`group_membership`  (
	`id`             	int(11) AUTO_INCREMENT NOT NULL,
	`group_id`       	int(11) NOT NULL,
	`member_id`      	int(11) NOT NULL,
	`membership_type`	int UNSIGNED COMMENT '1: User-Group, 2: Group-Group'  NULL DEFAULT '1',
	`createdBy`      	int(11) NULL,
	`createdAt`      	datetime(0) NULL,
	`modifiedBy`     	int(11) NULL,
	`modifiedAt`     	datetime(0) NULL,
	PRIMARY KEY(`id`)
);

ALTER TABLE `Authorization`.`group`
	ADD CONSTRAINT `role_name`
	UNIQUE (`name`);

ALTER TABLE `Authorization`.`group_membership`
	ADD CONSTRAINT `group_member_id`
	UNIQUE (`group_id`, `member_id`, `membership_type`);

ALTER TABLE `Authorization`.`group_membership`
	ADD CONSTRAINT `group_id`
	FOREIGN KEY(`group_id`)
	REFERENCES `group`(`id`);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "administrator",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "copilot",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "Delegate Policy Loader",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "Connect Manager",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "Connect Support",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "Connect Copilot",
  now(),
  now()
);

INSERT INTO `Authorization`.`role` (name, createdAt, modifiedAt) VALUES(
  "Topcoder User",
  now(),
  now()
);

INSERT INTO `Authorization`.`role_assignment` (role_id, subject_id, createdAt, modifiedAt) VALUES(
  1,
  1,
  now(),
  now()
);
