--SELECT DbName, NodeName, Node.ToString(), Level FROM eha.BackupActivity
DECLARE @ServerName NVARCHAR(128) = @@SERVERNAME -- 'nosuchsrv' is empty rs
DECLARE @DbName NVARCHAR(128) = 
--'master';
'ehdb';
--'nosuchdb';
DECLARE @NodeName NVARCHAR(128) = 
--'Service Master Key';
--'Database Master Key';
--'TDECertificate';
'ValueCertificate';
--'ObjectCertificate';
  DECLARE @Node HIERARCHYID;
 -- distinct because we allow the user to force duplicate backups  
  WITH cte 
    AS ( SELECT [DbName]
              , [NodeName]
              , [Node]
              , [Level]
              , action
         FROM eha.BackupActivity
         WHERE ServerName = @ServerName
         AND Action IN ( 'Install'                 -- level 0   
                       , 'BackupServiceMasterKey'  -- level 1
                       , 'BackupDatabaseMasterKey' -- level 2
                       , 'BackupCertificate' )     -- level 3
        AND Status = 'Complete')
  SELECT --@Node = 
          parent.Node.ToString() as parent
        , parent.Level as parentlevel
        , this.Node.ToString() as this
        , last.Node.ToString() as last  
        , parent.Node.GetDescendant( last.Node, NULL ).ToString() as next
        , ISNULL ( this.Node,  parent.Node.GetDescendant( last.Node, NULL ) ).ToString() as usethis
, *        
  FROM cte parent         
  CROSS APPLY ( SELECT MAX(Node) AS Node
                FROM cte 
                WHERE Node.GetAncestor(1) = parent.Node) AS last
  LEFT JOIN cte AS this
  ON this.Node.GetAncestor(1) = parent.Node
  AND this.DbName  = @DbName
  AND this.NodeName = @NodeName
  WHERE parent.Level =  CASE @NodeName  
                        WHEN 'Service Master Key'
                        THEN 0
                        WHEN 'Database Master Key'
                        THEN 1
                        ELSE 2 END
  AND parent.DbName = CASE WHEN parent.level = 2
                          THEN @DbName
                          WHEN parent.level = 1
                          THEN 'master'
                          ELSE '' END

--WITH cte 
-- AS ( SELECT [DbName]
--           , [NodeName]
--           , [Node]
--           , 0 AS Level
--      FROM eha.BackupActivity
--      WHERE NodeName = 'root'
--      AND DbName = ''
--      AND Action = 'Install'
--      AND Status = 'Complete' 
--      UNION ALL
--      SELECT [DbName]
--           , [NodeName]
--           , [Node]
--           , 1
--      FROM eha.BackupActivity
--      WHERE ServerName = @ServerName
--      AND DbName = 'master'
--      AND Action = 'BackupServiceMasterKey'
--      AND Status = 'Complete'
--            UNION ALL
--      SELECT [DbName]
--           , [NodeName]
--           , [Node]
--           , 2
--      FROM eha.BackupActivity
--      WHERE ServerName = @ServerName
--      AND DbName = @DbName
--      AND Action = 'BackupDatabaseMasterKey'
--      AND Status = 'Complete'
--            UNION ALL
--      SELECT [DbName]
--           , [NodeName]
--           , [Node]
--           , 3
--      FROM eha.BackupActivity
--      WHERE ServerName = @ServerName
--      AND DbName = @DbName
--      AND Action = 'BackupCertificate'
--      AND Status = 'Complete' )      
--  SELECT  --@Node = 
--      CASE WHEN existing.Node IS NULL
--          THEN parent.Node.GetDescendant(NULL, NULL).ToString()
--          WHEN existing.Node = this.Node               
--          THEN existing.Node.ToString()   
--          ELSE parent.Node.GetDescendant(existing.Node, NULL).ToString() END AS [UseThisOne]
-- , parent.Node.ToString() as parent, parent.*, this.Node.ToString() as this, this.*, existing.Node.ToString() as existing, existing.*
--  FROM cte AS parent 
--  LEFT JOIN cte as this
--  ON this.Node.GetAncestor(1) = parent.Node 
--  AND this.NodeName = @NodeName
--  AND this.DbName = @DbName
--  CROSS APPLY (SELECT MAX(Node) AS Node 
--               FROM cte
--               WHERE Node.GetAncestor(1) = parent.Node ) AS existing
--  WHERE parent.NodeName = @ParentName;

--select parent.NodeName as [parent name]
--     , parent.Node.ToString() as parent
--     , this.NodeName as [this node name] 
--     , this.Node.ToString() as this
--from cte this
--join cte parent
--ON this.Node.GetAncestor(1) = parent.Node
--WHERE this.NodeName = @NodeName
--AND  parent.NodeName = @ParentName
--AND this.DbName = @DbName
----AND parent.Level = this.Level - 1

----  existing.Node as [existing.Node] 
----, this.Node AS [this.Node]
----, parent.Node.GetDescendant(NULL, NULL).ToString() as [GetDescendant(NULL, NULL)]
----, existing.Node.ToString() as [existing.Node]
----, parent.Node.GetDescendant(existing.Node, NULL).ToString() as [GetDescendant(existing.Node, NULL)]
------SELECT  @Node = 
----    --CASE WHEN existing.Node IS NULL
----    --    THEN parent.Node.GetDescendant(NULL, NULL).ToString()
----    --    WHEN existing.Node = this.Node               
----    --    THEN existing.Node.ToString()   
----    --    ELSE parent.Node.GetDescendant(existing.Node, NULL).ToString() END 
----, parent.*, this.*, existing.*
----FROM cte AS parent 
----LEFT JOIN cte as this
----ON this.Node.GetAncestor(1) = parent.Node 
----AND this.Node = @Node
----LEFT JOIN cte AS existing
----ON existing.Node.GetAncestor(1) = parent.Node
----WHERE parent.NodeName = @ParentName
------select @Node, @Node.ToString(), @Node.GetAncestor(1);
