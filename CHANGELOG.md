# Changelog

## 2023-05-25 -- 2.1.0

* fixed issue with "search entity" and "search entity by id" in case of observable attached to entity with less then 6 digit number.
* Added support for public API V2, tested in ic-playground (release 3.0.0).
* Verified support of Public API V1, tested in release 2.14
* App version set to 2.1.0

## 2023-05-11 -- 2.0.1

* Added correct Splunk SOAR naming (replacing Splunk Phantom)

## 2023-04-28 -- 2.0.0

* Migrates code from Python v2 -> v3 to support Splunk SOAR EOS for Python v2
* Adds support for the EclecticIQ public API
* Contains updated playbook actions for;
  * domain reputation
  * email reputation
  * file reputation
  * ip reputation
  * url reputation
* Create sighting
* Query entities
* Adds 3 new flexible playbook actions (GET/POST/PUT) allowing for custom interaction with the IC API
