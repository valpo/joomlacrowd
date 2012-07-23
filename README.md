joomlacrowd
===========

Authorization and SSO for Joomla with Atlassian Crowd

This repo contains 2 Joomla plugins: 

crowd
=====

This is an authentication plugin used to enable authentication
against an atlassian crowd server. 

crowdsso
========

This as a system plugin enabling sso against atlassian 
crowd. 

Features
========

- authorization against crowd
- sso authorization (respects existing crowd token or sets it after successfull login)
- group sync (one-way: receives groups from crowd and add user to these groups, 
  removes user from all other groups)
- group mapping: map crowd groups to joomla group ids
- user removal: users removed from crowd will be removed from joomla on next
  login too

Installation
============

Create zips from both packages:
..../joomlacrowd: zip crowd.zip crowd/crowd.*
.../joomlacrowd: zip crowdsso.zip crowdsso/crowd.*

Install these zips as usual. You need both plugins!
Configure the plugins from withing joomal as usual. 

Debug
=====

Both plugins use the logfile debug.crowd.log. Check its 
contents, maybe its helpful. 


Known bugs or drawbacks
=======================

1. no i18n, no language files
