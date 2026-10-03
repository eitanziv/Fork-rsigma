SELECT * FROM security_events WHERE "EventType" ILIKE 'login\_success'
WITH combined_events AS (SELECT * FROM security_events WHERE "EventType" ILIKE 'login\_failure') SELECT "User", COUNT(*) AS event_count FROM combined_events GROUP BY "User" HAVING COUNT(*) >= 5
WITH matched AS (SELECT * FROM security_events WHERE rule_name IN ('many_failed_logins', 'successful_login') AND time >= NOW() - INTERVAL '3600 seconds') SELECT "User", COUNT(DISTINCT rule_name) AS distinct_rules, MIN(time) AS first_seen, MAX(time) AS last_seen FROM matched GROUP BY "User" HAVING COUNT(DISTINCT rule_name) >= 2
