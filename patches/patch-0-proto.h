*** epan/proto.h.orig	2016-07-01 15:43:16.000000000 +0200
--- epan/proto.h	2016-07-01 15:43:34.000000000 +0200
***************
*** 372,377 ****
--- 372,378 ----
  #define ENC_TIME_NTP                0x00000002	/* NTP times */
  #define ENC_TIME_TOD                0x00000004	/* System/3xx and z/Architecture time-of-day clock */
  #define ENC_TIME_NTP_BASE_ZERO      0x00000008  /* NTP times with different BASETIME */
+ #define ENC_TIME_NANOS_TIME_T       0x00000010  /* Nanseconds since the UNIX epoch */
  /*
   * Historically, the only place the representation mattered for strings
   * was with FT_UINT_STRINGs, where we had FALSE for the string length
