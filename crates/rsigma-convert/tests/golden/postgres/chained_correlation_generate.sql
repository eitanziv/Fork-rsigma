WITH combined_events AS (SELECT * FROM security_events WHERE "EventType" = 'login_failure') SELECT "User", COUNT(*) AS event_count FROM combined_events GROUP BY "User" HAVING COUNT(*) >= 5
SELECT "User", COUNT(*) AS event_count FROM security_events WHERE time >= NOW() - INTERVAL '3600 seconds' GROUP BY "User" HAVING COUNT(*) >= 3
