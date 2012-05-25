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

Installation
============

Create zips from both packages:
..../joomlacrowd: zip crowd.zip crowd/crowd.*
.../joomlacrowd: zip crowdsso.zip crowdsso/crowd.*

Install these zips as usual. 

Debug
=====

Both plugins use the logfile debug.crowd.log. Check its 
contents, maybe its helpful. 


Known bugs or drawbacks
=======================

1. no i18n, no language files
