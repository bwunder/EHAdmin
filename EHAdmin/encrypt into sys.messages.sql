--put encrypted message into sys.messages
DECLARE @msg NVARCHAR(255), @secret NVARCHAR(255) ;

SET @msg = N'test message';
SELECT @msg AS [@msg]
SET @secret = ENCRYPTBYPASSPHRASE( 'test phrase', @msg );
SELECT @msg AS [@msg] 
     , CAST( @secret AS VARBINARY(8000) ) AS [@secret]
     , CAST( DECRYPTBYPASSPHRASE( 'test phrase'
                                , CAST( @secret AS VARBINARY(8000) ) ) AS NVARCHAR(255) ) AS [@secret (deciphered)] 

EXEC sp_addmessage 500002, 16, @secret, 'us_english', 'FALSE', 'replace'
SELECT text AS [text from sys.messages] 
  , CAST(text AS VARBINARY(8000) ) AS [text of msg 500002]
  , FORMATMESSAGE(500002) AS [text of msg 500002]
  , CAST(FORMATMESSAGE(500002) AS VARBINARY(8000))
  , CAST( DECRYPTBYPASSPHRASE( 'test phrase'
                            , CAST( FORMATMESSAGE(500002) AS VARBINARY(8000) ) ) AS NVARCHAR(255) ) AS [50002 (deciphered)]
FROM sys.messages 
WHERE message_id = 500002;


EXEC sp_dropmessage 500002;


