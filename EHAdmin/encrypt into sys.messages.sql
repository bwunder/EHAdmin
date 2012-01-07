--put encrypted message into sys.messages
declare @msg NVARCHAR(1024), @emsg VARBINARY(8000), @cemsg NVARCHAR(2048);
set @msg = 'test message';
set @emsg = EncryptByPassPhrase('test phrase', @msg);
set @cemsg = sys.fn_varbintohexstr( @emsg );
EXEC sp_addmessage 500002, 16, @cemsg, 'us_english', 'FALSE', 'replace'
select text from sys.messages where message_id in ( 500001, 500002 );
select @msg as [@msg]
select @emsg as [@emsg]
select @cemsg as [@cemsg]
select FORMATMESSAGE(500002) AS [500002]
select CAST(decryptbypassphrase('test phrase',@emsg ) as nvarchar(1024) ) as [@emsg result] 
select CAST(decryptbypassphrase('test phrase', FORMATMESSAGE(500001) ) as nvarchar(1024) ) as [500001 result] 
select CAST(decryptbypassphrase('test phrase', FORMATMESSAGE(500002) ) as nvarchar(1024) ) as [500002 result] 
EXEC sp_dropmessage 500002;

