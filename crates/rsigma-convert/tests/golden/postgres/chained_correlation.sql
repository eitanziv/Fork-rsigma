SELECT "User", COUNT(*) AS event_count FROM security_events WHERE time >= NOW() - INTERVAL '3600 seconds' GROUP BY "User" HAVING COUNT(*) >= 3
