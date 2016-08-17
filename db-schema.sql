CREATE schema nfcollect;

--DROP TABLE nfcollect.log_items;
CREATE TABLE IF NOT EXISTS nfcollect.log_items (
 event_time         bigint
,src_addr           inet
,dst_addr           inet
,dst_port           integer
,xlate_src_addr     inet
,xlate_src_port     integer
,protocol           integer
);

CREATE OR REPLACE FUNCTION
nfcollect.log_items_partition_function()
RETURNS TRIGGER AS 
$BODY$
    DECLARE
        _new_time int;
        _tablename text;
        _startdate text;
        _enddate text;
        _result record;
    BEGIN
    --Takes the current inbound "time" value and determines when midnight is for the given date
    _new_time := ((NEW.event_time/86400)::int)*86400;
    _startdate := to_char(to_timestamp(_new_time), 'YYYY-MM-DD');
    _tablename := 'log_items_'||_startdate;

    -- Check if the partition needed for the current record exists
    PERFORM 1
    FROM   pg_catalog.pg_class c
    JOIN   pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE  c.relkind = 'r'
    AND    c.relname = _tablename
    AND    n.nspname = 'nfcollect';

    -- If the partition needed does not yet exist, then we create it:
    -- Note that || is string concatenation (joining two strings to make one)
    IF NOT FOUND THEN
    _enddate:=_startdate::timestamp + INTERVAL '1 day';
    EXECUTE 'CREATE TABLE IF NOT EXISTS nfcollect.' || quote_ident(_tablename) || ' (
    CHECK ( event_time >= EXTRACT(EPOCH FROM DATE ' || quote_literal(_startdate) || ')
    AND event_time < EXTRACT(EPOCH FROM DATE ' || quote_literal(_enddate) || ')
    )
    ) INHERITS (nfcollect.log_items)';

    -- Table permissions are not inherited from the parent.
    -- If permissions change on the master be sure to change them on the child also.
    EXECUTE 'ALTER TABLE nfcollect.' || quote_ident(_tablename) || ' OWNER TO nfcollect';
    EXECUTE 'GRANT ALL ON TABLE nfcollect.' || quote_ident(_tablename) || ' TO nfcollect';

    -- Indexes are defined per child, so we assign a default index that uses the partition columns
    EXECUTE 'CREATE INDEX ' || quote_ident(_tablename||'_indx1') || ' ON nfcollect.' || quote_ident(_tablename) || ' (event_time)';
    EXECUTE 'CREATE INDEX ' || quote_ident(_tablename||'_indx2') || ' ON nfcollect.' || quote_ident(_tablename) || ' (xlate_src_addr)';
    EXECUTE 'CREATE INDEX ' || quote_ident(_tablename||'_indx3') || ' ON nfcollect.' || quote_ident(_tablename) || ' (dst_addr)';
    END IF;

    -- Insert the current record into the correct partition, which we are sure will now exist.
    EXECUTE 'INSERT INTO nfcollect.' || quote_ident(_tablename) || ' VALUES ($1.*)' USING NEW;
    RETURN NULL;
    END;
$BODY$
LANGUAGE plpgsql;

CREATE TRIGGER log_items_trigger
BEFORE INSERT ON nfcollect.log_items
FOR EACH ROW EXECUTE PROCEDURE nfcollect.log_items_partition_function();
