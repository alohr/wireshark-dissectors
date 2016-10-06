*** epan/proto.c.orig	2016-07-01 15:43:48.000000000 +0200
--- epan/proto.c	2016-07-01 15:46:55.000000000 +0200
***************
*** 1783,1789 ****
  			}
  			break;
  
! 		default:
  			DISSECTOR_ASSERT_NOT_REACHED();
  			break;
  	}
--- 1783,1816 ----
  			}
  			break;
  
! 	        case ENC_TIME_NANOS_TIME_T|ENC_BIG_ENDIAN:
! 			/*
! 			 * Nanoseconds since UNIX epoch, big-endian.
! 			 */
! 			if (length != 8) {
! 				REPORT_DISSECTOR_BUG(wmem_strdup_printf(wmem_packet_scope(),
!                                         "Invalid length %d for ENC_TIME_NANOS_TIME_T", length));
! 				break;
! 			}
! 			todsecs = tvb_get_ntoh64(tvb, start);
! 			time_stamp->secs = todsecs / (time_t)1000000000;
! 			time_stamp->nsecs = (int)(todsecs % (time_t)1000000000);
! 			break;
! 	        case ENC_TIME_NANOS_TIME_T|ENC_LITTLE_ENDIAN:
! 			/*
! 			 * Nanoseconds since UNIX epoch, little-endian.
! 			 */
! 			if (length != 8) {
! 				REPORT_DISSECTOR_BUG(wmem_strdup_printf(wmem_packet_scope(),
!                                         "Invalid length %d for ENC_TIME_NANOS_TIME_T", length));
! 				break;
! 			}
! 			todsecs = tvb_get_letoh64(tvb, start);
! 			time_stamp->secs = todsecs / (time_t)1000000000;
! 			time_stamp->nsecs = (int)(todsecs % (time_t)1000000000);
! 			break;
! 
! 	default:
  			DISSECTOR_ASSERT_NOT_REACHED();
  			break;
  	}
