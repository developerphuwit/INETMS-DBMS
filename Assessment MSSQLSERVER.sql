--Assessment

--Linked Update service pacth: https://support.microsoft.com/en-us/servicing/sql/sql-server-2025/kb5005684-build-versions
--CIS Doc: --https://downloads.cisecurity.org/#/

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Configuration details
DECLARE @Statisticports NVARCHAR(10), 
		@Dynamicports NVARCHAR(10),
		@Numberoferrorlogs INT,
		@Errorlogpersizekb INT,
		@AuditLevel int

	EXEC xp_instance_regread  
		N'HKEY_LOCAL_MACHINE',  
		N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',  
		N'TcpPort',  
		@Statisticports OUTPUT;

	EXEC xp_instance_regread  
		N'HKEY_LOCAL_MACHINE',  
		N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',  
		N'TcpDynamicPorts',  
		@Dynamicports OUTPUT;

	EXEC xp_instance_regread 
		N'HKEY_LOCAL_MACHINE', 
		N'Software\Microsoft\MSSQLServer\MSSQLServer', 
		N'NumErrorLogs',
		@Numberoferrorlogs OUTPUT;

	EXEC xp_instance_regread 
		N'HKEY_LOCAL_MACHINE', 
		N'Software\Microsoft\MSSQLServer\MSSQLServer', 
		N'ErrorLogSizeInKb',
		@Errorlogpersizekb OUTPUT;

	EXEC xp_instance_regread 
		'HKEY_LOCAL_MACHINE',
		'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer',
		'AuditLevel',
		@value=@AuditLevel output

SELECT 
    sqlserver_start_time AS 'Start_time_on_service', 
    @@SERVERNAME AS 'INSTANCE NAME',          
    @@VERSION AS 'SQLSERVER VERSION',
    SERVERPROPERTY('IsClustered') AS 'IsClustered',
    SERVERPROPERTY('IsXTPSupported') AS 'IsXTPSupported',
    @Statisticports AS 'Static Port', 
    @Dynamicports AS 'Dynamic Port',
	cpu_count AS 'CPU_Cores',
    (SELECT physical_name FROM sys.master_files WHERE name = 'master') AS 'Root Directory',
    SERVERPROPERTY('Collation') AS 'Server Collation',
    (physical_memory_kb / 1024) AS Total_Physical_Memory_GB,
    (SELECT value_in_use FROM sys.configurations WHERE name = 'min server memory (MB)') AS Min_Server_Memory_MB,
    (SELECT value_in_use FROM sys.configurations WHERE name = 'max server memory (MB)') AS Max_Server_Memory_MB,
    (committed_kb / 1024) AS SQLServer_Used_Memory_MB,
    (CASE 
        WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'Windows Authentication mode'
        WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 0 THEN 'SQLSERVER and Windows Authentication mode'
    END) AS 'Authentication Mode',
	(CASE 
        WHEN @AuditLevel = 0 THEN 'None'
        WHEN @AuditLevel = 1 THEN 'Successful Logins Only'
		WHEN @AuditLevel = 2 THEN 'Failed Logins Only'
        WHEN @AuditLevel = 3 THEN 'Both Failed and Successful Logins'
    END) as 'Login auditing',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'show advanced options') AS 'show advanced options',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'c2 audit mode') AS 'c2 audit mode',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'common criteria compliance enabled') AS 'common criteria compliance enabled',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'user connections') AS 'user connections',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'query governor cost limit') AS 'query governor cost limit',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'remote access') AS 'remote access',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'remote query timeout (s)') AS 'remote query timeout (s)',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'remote proc trans') AS 'remote proc trans',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'fill factor (%)') AS 'fill factor (%)',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'media retention') AS 'Default backup media retention (in days)',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'backup compression default') AS 'Compress backup',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'backup checksum default') AS 'Backup checksum',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'recovery interval (min)') AS 'recovery interval (min)',
    SERVERPROPERTY('InstanceDefaultDataPath') AS 'Default Data Path',
    SERVERPROPERTY('InstanceDefaultLogPath') AS 'Default Log Path',
    SERVERPROPERTY('InstanceDefaultBackupPath') AS 'Default Backup Path',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries') AS 'Ad Hoc Distributed Queries',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'CLR Enabled') AS 'CLR Enabled',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Cross DB Ownership Chaining') AS 'Cross DB Ownership Chaining',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs') AS 'Database Mail XPs',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures') AS 'Ole Automation Procedures',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Remote Access') AS 'Remote Access',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Remote Admin Connections') AS 'Remote Admin Connections',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'Scan For Startup Procs') AS 'Scan For Startup Procs',
    (SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell') AS 'xp_cmdshell',
	@Numberoferrorlogs AS 'Number of error logs',
	@Errorlogpersizekb AS 'Error log size in KB',
	GETDATE() AS 'Update time'
    FROM sys.dm_os_sys_info;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Total storage on server
SELECT DISTINCT 
    vs.volume_mount_point AS Drive,
    vs.file_system_type AS FileSystem,
    vs.total_bytes / 1024.00 / 1024.00 / 1024.00 AS Total_Size_GB,
    vs.available_bytes / 1024.00 / 1024.00 / 1024.00 AS Available_Size_GB,
    (vs.total_bytes - vs.available_bytes) / 1024.00 / 1024.00 / 1024.00 AS Used_Size_GB,
    ((vs.total_bytes - vs.available_bytes) * 100.00 / vs.total_bytes) AS Usage_Percentage,
	GETDATE() AS 'Time_stamp'
    FROM sys.master_files AS mf
CROSS APPLY sys.dm_os_volume_stats(mf.database_id, mf.file_id) AS vs;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Database Status + Configure
WITH fs AS 
(
    SELECT 
        database_id, 
        type, 
        physical_name,
        [size] = CAST(Size AS BIGINT)*8 /1024
    FROM sys.master_files
)
SELECT
    db.database_id AS "Database_ID",
	db.name AS "Database_Name",
    SUSER_SNAME(db.owner_sid) AS "Database_Owner",
    db.state_desc AS "Status",
    db.recovery_model_desc AS "Recovery Model",
    db.compatibility_level AS "Compatibility Level",
    db.collation_name AS "Collation Name",
    db.is_read_only AS "Read-only Status",
    db.is_trustworthy_on AS "Trustworthy",
    db.is_db_chaining_on AS "Database Chaining",
    db.is_encrypted AS "Encryption Status",
    (SELECT SUM(size) FROM fs WHERE type = 0 AND fs.database_id = db.database_id) AS DataFileMB,
    (SELECT SUM(size) FROM fs WHERE type = 1 AND fs.database_id = db.database_id) AS LogFileMB, 
    ((SELECT SUM(size) FROM fs WHERE type = 0 AND fs.database_id = db.database_id) +
     (SELECT SUM(size) FROM fs WHERE type = 1 AND fs.database_id = db.database_id)) AS TotalMB,
    GETDATE() AS "Update Date"
FROM sys.databases db;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Database path
SELECT 
    db.name AS Database_Name,
	(CASE mf.type_desc
		WHEN 'ROWS' THEN 'Data files' 
		WHEN 'LOG' THEN 'LOG files' END) AS 'File Type',
    mf.physical_name AS File_Path,
    CAST(Size AS BIGINT)*8 /1024 AS File_Size_MB,
    GETDATE() AS Update_Date
FROM sys.databases db
JOIN sys.master_files mf ON db.database_id = mf.database_id
ORDER BY db.name, mf.type_desc;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Get All Server roles (ไม่รวม Roles ที่ขึ้นต้นด้วย ##)
DECLARE @DynamicSQL NVARCHAR(MAX);
DECLARE @ColumnList NVARCHAR(MAX) = '';
DECLARE @JoinList NVARCHAR(MAX) = '';

    -- ดึงชื่อ Server Roles ที่ไม่ขึ้นต้นด้วย ## จาก sys.server_principals
        SELECT @ColumnList = STUFF(
        (SELECT ', ISNULL(roles.' + QUOTENAME(name) + ', 0) AS ' + QUOTENAME(name) 
        FROM sys.server_principals 
        WHERE type_desc = 'SERVER_ROLE'
        AND name NOT LIKE '##%'
        FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 2, '');

    -- สร้าง Dynamic Columns สำหรับตรวจสอบ Role ใน JOIN
        SELECT @JoinList = STUFF(
        (SELECT ', MAX(CASE WHEN spr.name = ' + QUOTENAME(name, '''') + ' THEN 1 ELSE 0 END) AS ' + QUOTENAME(name)
        FROM sys.server_principals 
        WHERE type_desc = 'SERVER_ROLE'
        AND name NOT LIKE '##%'
        FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 2, '');

    -- สร้าง Dynamic SQL
        SET @DynamicSQL = '
        SELECT 
            inet.name AS LoginName, 
            inet.type_desc AS LoginType, 
            CASE inet.is_disabled 
                WHEN 1 THEN ''Disabled''
                WHEN 0 THEN ''Enabled'' 
            END AS Login_status,
            ms.is_policy_checked AS Enforce_Password_Policy,   
            ms.is_expiration_checked AS Enforce_Password_Expiration,
            ' + @ColumnList + '
        FROM sys.server_principals inet
        LEFT JOIN (
            SELECT dbms.member_principal_id, ' + @JoinList + '
            FROM sys.server_role_members dbms
            JOIN sys.server_principals spr ON dbms.role_principal_id = spr.principal_id
            GROUP BY dbms.member_principal_id
        ) roles ON inet.principal_id = roles.member_principal_id
            LEFT JOIN sys.sql_logins ms ON inet.principal_id = ms.principal_id 
        WHERE inet.type_desc IN (''SQL_LOGIN'', ''WINDOWS_LOGIN'', ''WINDOWS_GROUP'')
        ORDER BY inet.name;';

    -- รัน Dynamic SQL
        EXEC sp_executesql @DynamicSQL;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- User Mapping
    -- สร้าง Temporary Table สำหรับเก็บผลลัพธ์
        IF OBJECT_ID('tempdb..#UserMapping') IS NOT NULL
        DROP TABLE #UserMapping;

        CREATE TABLE #UserMapping (
        database_name NVARCHAR(128),
        role_principal_name NVARCHAR(128),
        member_principal_name NVARCHAR(128)
        );

    -- ใช้ sp_MSforeachdb เพื่อ loop ผ่านทุกฐานข้อมูล
        EXEC sp_MSforeachdb N'
        USE [?];
        INSERT INTO #UserMapping
            SELECT 
            DB_NAME() AS database_name,       
            r.name AS role_principal_name,    
            m.name AS member_principal_name   
        FROM sys.database_role_members rm 
        JOIN sys.database_principals r 
        ON rm.role_principal_id = r.principal_id   
        JOIN sys.database_principals m 
        ON rm.member_principal_id = m.principal_id;';

    -- ดึงข้อมูลที่รวมไว้แล้ว
        SELECT * FROM #UserMapping ORDER BY database_name, role_principal_name, member_principal_name;

    -- เคลียร์ Temp Table (ถ้าต้องการ)
        DROP TABLE #UserMapping;

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Credential details
SELECT name,credential_identity AS 'Owner', create_date FROM sys.credentials

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Server OBJECT
	--Linked Server
	SELECT name, product , provider,data_source , modify_date FROM sys.servers
		
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Replication
--Replication
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'distribution')
BEGIN
    -- Publication
    SELECT
         S.[name]            AS [Publisher Hostname],  
         P.[publication]      AS [Publication Name],   
         A.[publisher_db]     AS [Database Name],         
         A.[source_owner]     AS [Schema],             
         A.[source_object]    AS [Source Table],       
         A.[destination_object] AS [Destination Table] 
    FROM
        [distribution].[dbo].[MSarticles] AS A
        INNER JOIN [distribution].[dbo].[MSpublications] AS P
            ON A.[publication_id] = P.[publication_id]
        INNER JOIN sys.servers S 
            ON S.server_id = 0  
    ORDER BY
        S.[name], P.[publication], A.[article];
	--Subscription
	SELECT [publisher],[subscriber] FROM [distribution].[dbo].[MSsubscriber_info]
END
ELSE
BEGIN
    PRINT 'Database "distribution" not found. Skipping replication query.';
END

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- Log Shipping on primary
SELECT 
    *
FROM msdb.dbo.log_shipping_monitor_primary;

-- Log Shipping on secondary
SELECT 
    *
FROM msdb.dbo.log_shipping_monitor_secondary;


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--Always on High availability
--Check ListenerName and IPAddress
SELECT 
    ag.name AS AvailabilityGroupName,
    agl.dns_name AS ListenerName,
    agl.port AS ListenerPort,
    aglip.ip_address AS IPAddress,
    aglip.is_dhcp AS IsDHCP
    FROM sys.availability_groups ag
    JOIN sys.availability_group_listeners agl 
    ON ag.group_id = agl.group_id
    JOIN sys.availability_group_listener_ip_addresses aglip 
    ON agl.listener_id = aglip.listener_id;



------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Number of Error logs 
DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
@NumErrorLogs OUTPUT;
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Path Error Log
SELECT    @@servername as ServerName
        , RIGHT(cast(value_data as nvarchar(max)), LEN(cast(value_data as nvarchar(max))) - 2) as ErrorLogLocation
FROM sys.dm_server_registry
where value_name = 'SQLArg1' -- this is the error log location

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Check list job and owner 
SELECT INET.name AS JobName,IIF( INET.enabled = 1, 'Enabled', 'Disabled') as 'Enabled', MS.name AS JobOwner
FROM msdb..sysjobs INET
LEFT JOIN master.sys.syslogins MS ON INET.owner_sid = MS.sid
WHERE MS.name IS NOT NULL
ORDER by INET.name

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Audit Log
SELECT 
   name , status_desc , status_time , audit_file_path
FROM sys.dm_server_audit_status;
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Check Certificate
select name, start_date, expiry_date from sys.certificates;
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--Check Always on High availability Status
SET NOCOUNT ON;
    DECLARE @AGname NVARCHAR(128);
    DECLARE @SecondaryReplicasOnly BIT;
    SET @AGname = 'AG1';        --SET AGname for a specific AG for SET to NULL for ALL AG's
    IF OBJECT_ID('TempDB..#tmpag_availability_groups') IS NOT NULL
    DROP TABLE [#tmpag_availability_groups];
    SELECT *
    INTO [#tmpag_availability_groups]
    FROM   [master].[sys].[availability_groups];
 
    IF(@AGname IS NULL
    OR EXISTS
    (
    SELECT [Name]
    FROM   [#tmpag_availability_groups]
    WHERE  [Name] = @AGname
    ))
        BEGIN
        IF OBJECT_ID('TempDB..#tmpdbr_availability_replicas') IS NOT NULL
        DROP TABLE [#tmpdbr_availability_replicas];
 
        IF OBJECT_ID('TempDB..#tmpdbr_database_replica_cluster_states') IS NOT NULL
        DROP TABLE [#tmpdbr_database_replica_cluster_states];
 
        IF OBJECT_ID('TempDB..#tmpdbr_database_replica_states') IS NOT NULL
        DROP TABLE [#tmpdbr_database_replica_states];
 
        IF OBJECT_ID('TempDB..#tmpdbr_database_replica_states_primary_LCT') IS NOT NULL
        DROP TABLE [#tmpdbr_database_replica_states_primary_LCT];
 
        IF OBJECT_ID('TempDB..#tmpdbr_availability_replica_states') IS NOT NULL
        DROP TABLE [#tmpdbr_availability_replica_states];
 
        SELECT [group_id],
        [replica_id],
        [replica_server_name],
        [availability_mode],
        [availability_mode_desc]
        INTO [#tmpdbr_availability_replicas]
        FROM   [master].[sys].[availability_replicas];
 
        SELECT [replica_id],
        [group_database_id],
        [database_name],
        [is_database_joined],
        [is_failover_ready]
        INTO [#tmpdbr_database_replica_cluster_states]
        FROM   [master].[sys].[dm_hadr_database_replica_cluster_states];
 
        SELECT *
        INTO [#tmpdbr_database_replica_states]
        FROM   [master].[sys].[dm_hadr_database_replica_states];
 
        SELECT [replica_id],
        [role],
        [role_desc],
        [is_local]
        INTO [#tmpdbr_availability_replica_states]
        FROM   [master].[sys].[dm_hadr_availability_replica_states];
 
        SELECT [ars].[role],
        [drs].[database_id],
        [drs].[replica_id],
        [drs].[last_commit_time]
        INTO [#tmpdbr_database_replica_states_primary_LCT]
        FROM   [#tmpdbr_database_replica_states] AS [drs]
        LEFT JOIN [#tmpdbr_availability_replica_states] [ars] ON [drs].[replica_id] = [ars].[replica_id]
        WHERE  [ars].[role] = 1;
 
        SELECT [AG].[name] AS [AvailabilityGroupName],
        [AR].[replica_server_name] AS [AvailabilityReplicaServerName],
        [dbcs].[database_name] AS [AvailabilityDatabaseName],
        ISNULL([dbcs].[is_failover_ready],0) AS [IsFailoverReady],
        ISNULL([arstates].[role_desc],3) AS [ReplicaRole],
        [AR].[availability_mode_desc] AS [AvailabilityMode],
        CASE [dbcs].[is_failover_ready]
        WHEN 1
        THEN 0
        ELSE ISNULL(DATEDIFF([ss],[dbr].[last_commit_time],[dbrp].[last_commit_time]),0)
        END AS [EstimatedDataLoss_(Seconds)],
        ISNULL(CASE [dbr].[redo_rate]
        WHEN 0
        THEN-1
        ELSE CAST([dbr].[redo_queue_size] AS FLOAT) / [dbr].[redo_rate]
        END,-1) AS [EstimatedRecoveryTime_(Seconds)],
        ISNULL([dbr].[is_suspended],0) AS [IsSuspended],
        ISNULL([dbr].[suspend_reason_desc],'-') AS [SuspendReason],
        ISNULL([dbr].[synchronization_state_desc],0) AS [SynchronizationState],
        ISNULL([dbr].[last_received_time],0) AS [LastReceivedTime],
        ISNULL([dbr].[last_redone_time],0) AS [LastRedoneTime],
        ISNULL([dbr].[last_sent_time],0) AS [LastSentTime],
        ISNULL([dbr].[log_send_queue_size],-1) AS [LogSendQueueSize],
        ISNULL([dbr].[log_send_rate],-1) AS [LogSendRate_KB/S],
        ISNULL([dbr].[redo_queue_size],-1) AS [RedoQueueSize_KB],
        ISNULL([dbr].[redo_rate],-1) AS [RedoRate_KB/S],
        ISNULL(CASE [dbr].[log_send_rate]
        WHEN 0
        THEN-1
        ELSE CAST([dbr].[log_send_queue_size] AS FLOAT) / [dbr].[log_send_rate]
        END,-1) AS [SynchronizationPerformance],
        ISNULL([dbr].[filestream_send_rate],-1) AS [FileStreamSendRate],
        ISNULL([dbcs].[is_database_joined],0) AS [IsJoined],
        [arstates].[is_local] AS [IsLocal],
        ISNULL([dbr].[last_commit_lsn],0) AS [LastCommitLSN],
        ISNULL([dbr].[last_commit_time],0) AS [LastCommitTime],
        ISNULL([dbr].[last_hardened_lsn],0) AS [LastHardenedLSN],
        ISNULL([dbr].[last_hardened_time],0) AS [LastHardenedTime],
        ISNULL([dbr].[last_received_lsn],0) AS [LastReceivedLSN],
        ISNULL([dbr].[last_redone_lsn],0) AS [LastRedoneLSN]
        FROM   [#tmpag_availability_groups] AS [AG]
        INNER JOIN [#tmpdbr_availability_replicas] AS [AR] ON [AR].[group_id] = [AG].[group_id]
        INNER JOIN [#tmpdbr_database_replica_cluster_states] AS [dbcs] ON [dbcs].[replica_id] = [AR].[replica_id]
        LEFT OUTER JOIN [#tmpdbr_database_replica_states] AS [dbr] ON [dbcs].[replica_id] = [dbr].[replica_id]
        AND [dbcs].[group_database_id] = [dbr].[group_database_id]
        LEFT OUTER JOIN [#tmpdbr_database_replica_states_primary_LCT] AS [dbrp] ON [dbr].[database_id] = [dbrp].[database_id]
        INNER JOIN [#tmpdbr_availability_replica_states] AS [arstates] ON [arstates].[replica_id] = [AR].[replica_id]
        WHERE  [AG].[name] = ISNULL(@AGname,[AG].[name])
        ORDER BY [AvailabilityReplicaServerName] ASC,
        [AvailabilityDatabaseName] ASC;
 
        /*********************/
        
        END;
        ELSE
        BEGIN
        RAISERROR('Invalid AG name supplied, please correct and try again',12,0);
        END;

