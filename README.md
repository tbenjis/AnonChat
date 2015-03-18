AnonChat is a p2p messaging application based on jTorChat. Application has been modified to use Off-The-Record messaging protocol and SMP (Socialist Millionaire Protocol). Updated to the latest Tor binary and other security improvement.

	
Design Goals
=============
1.	Users cannot be personally identified by their contacts or address.
2.	Contact lists, message history or metadata cannot be accessed by an intruder or server.
3.	All communication is encrypted and previous messages cannot be decrypted even if the encryption key is known.
4.	The system is completely decentralized and no server infrastructure is required.
5.	Enable users to resist censorship or monitoring in an unfavorable network environment.
6.	Registration of users is free and no personal details are required.
7.	User’s communicating can authenticate each other without exposing personal information.
8.	Available on different platforms without the need for configuration by the user.


Transport
===========
Uses TCP sockets to hidden services running on a specified port.
Peers send and receive messages on that TCP socket.


Connections
================
Hidden services behave like regular server sockets except that the server has no idea who (in the sense of IP source address) the client is because it is a tor client. As AnonChat is p2p, it needs to make out-bound connections to send messages and allow in-bound connections to receive messages from other peers.


Out-Bound Connections
======================
Connections to AnonChat peers are out-bound and are authenticated by definition as only the owner of the hidden service key is able to respond to the connection attempt.


In-Bound Connections
=====================
Connections from other AnonChat peers are always unauthenticated except they can prove in some way that they are who they pretend to be. AnonChat uses an session token for each peer to authenticate their connection and only then we can believe the claimed origin of the messages we receive on that in-bound connection.


Message Format
===============

<pre>
type: byte array
message separator: 0x0a (LF)
decode as string:
replace '\r\n' with '\n' then '\n' with "\n" (LF)
</pre>

Message Encryption Format
=========================

<pre>
command: /otr message
seperator: 0x20 (SP)
payload: string

Example:
/otr how are you?
</pre>

SMP Commands
============

<pre>
command: /otr /smpcmd  
seperator: 0x20 (SP)
payload: string
Example (/smpcmd): (/isq, /rs, /disc ...)
</pre>

Command Format
=================

<pre>
command: /command
seperator: 0x20 (SP)
payload: byte array

Example:
ping <payload>
</pre>

Message Commands
===================
`payload: <origin_hidden_service_id><separator><authentication_cookie>`

`<origin_hidden_service_id>` is the hash of the public key used in the onion network (also known as onion address). This is the address the peer needs to contact to return the authentication_cookie. This way the origin knows on which in-bound connection the peer sits on as the authentication_cookie was only sent to a single hidden service.

`<authentication_cookie>` is a string of no specific length, but should be 7-bit-only to avoid charset conversion issues.

This authentication cookie has to be unique, cryptographically random and kept secret! If this token leaks, anyone can impersonate the identity of that AnonChat peer as long as the AnonChat application which generated this token runs.

Example:

<pre>
ping jgustszdg6qnk6dh J8BQHZ0E0EDN58POQMPK7W6EA5UEXSEIYB37MR4YL6K6I0WLI1NX4ZOS3PVMMMOMRKXI15ZZ6D51I

pong J8BQHZ0E0EDN58POQMPK7W6EA5UEXSEIYB37MR4YL6K6I0WLI1NX4ZOS3PVMMMOMRKXI15ZZ6D51I
^ response command
</pre>

Sample Transcript
=================
<pre>
[6:04:56 - core.Buddy] Send afcgsnfdkz2irjrn pong 19A7FVNREG4X6PA0XGOXMGUTFW92WRAZFV403A5KXCYKI8CWTABMLGRSQHZQWYAKUAIDVH3UX6B92
[6:04:56 - core.Buddy] Sent afcgsnfdkz2irjrn a cached pong
[6:04:57 - core.Buddy] afcgsnfdkz2irjrn sent pong
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn client AnonChat
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn version 1.0.0 
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn profile_name memeto
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn profile_text 
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn add_me
[6:04:57 - core.Buddy] Send afcgsnfdkz2irjrn status available
[6:04:57 - API] afcgsnfdkz2irjrn name changed from  to youlava
[6:04:57 - API] afcgsnfdkz2irjrn profileText changed from  to 
[6:04:57 - API] afcgsnfdkz2irjrn requested us to add them
[6:04:57 - API] afcgsnfdkz2irjrn status change from Handshake to Online
[6:05:09 - IN_OTR] Converting to OTR:25:initiating OTR Encryption
[6:05:09 - java.lang.Class] Injecting message to the recipient:54: /otr initiating OTR Encryption 	  				 	 	 	    		  	 
[6:05:09 - core.Buddy] Send afcgsnfdkz2irjrn message /otr initiating OTR Encryption 	  				 	 	 	    		  	 
[6:05:09 - IN_OTR] Null received, maybe OTR control message

[6:05:10 - API] afcgsnfdkz2irjrn sent ?OTR:AAICAAAAxAv3crmvytrPHwpUZ5ZpDkPrzb50YBnpFriXOTaoGHDz0sUVM1xDPB0vS+gqvZFsJ6nSJO/aRpEevRT6/GUdNSnvWyKB/UXoXSwm57weMemvpj8uc9+e6bk1HU4YQfPYFtKWk4/bDU73WNVsw00Wijs2RKVzzNc7lmDC+OMf/KQm7vk+yFsGK25CVn9G9/afn94Q2zdBXFQSVr3bqquJVrJzyNHW0Onu/dFW6l0SkxDTGjvjxejnzxB56UbIYakeWGEPBiQAAAAgapxibcJ+rxRLoC3F9R0j5VOSGBS/lE0YsWJZc0CWSZk=.
[6:05:10 - OUT_OTR] From network:326: ?OTR:AAICAAAAxAv3crmvytrPHwpUZ5ZpDkPrzb50YBnpFriXOTaoGHDz0sUVM1xDPB0vS+gqvZFsJ6nSJO/aRpEevRT6/GUdNSnvWyKB/UXoXSwm57weMemvpj8uc9+e6bk1HU4YQfPYFtKWk4/bDU73WNVsw00Wijs2RKVzzNc7lmDC+OMf/KQm7vk+yFsGK25CVn9G9/afn94Q2zdBXFQSVr3bqquJVrJzyNHW0Onu/dFW6l0SkxDTGjvjxejnzxB56UbIYakeWGEPBiQAAAAgapxibcJ+rxRLoC3F9R0j5VOSGBS/lE0YsWJZc0CWSZk=.
[6:05:11 - java.lang.Class] Injecting message to the recipient:274: ?OTR:AAIKAAAAwML5kkOHNlAfYEgGX5/E4ajkYavTgICaZQMOxKquilq5pyaw1lN8it9+t0St3Ep0d2cfy5XAlhqpTzxDXYcs75zbQQIS2xqrpMLbYelQJeiF0Ov0R+5BJjLs68GnlPWAwTqX6ymqvmxzvV2NRB+9YYRYst8aY3peXG6bseojlA04pzDdH5N5P2zqt0OsGetwT2RRkkeHmIro/PxeIh0CV1HNjglBCRFoOaxHmAkrL2h2FS70SyKPB1VmwYxx6l6CGA==.
[6:05:11 - core.Buddy] Send afcgsnfdkz2irjrn message ?OTR:AAIKAAAAwML5kkOHNlAfYEgGX5/E4ajkYavTgICaZQMOxKquilq5pyaw1lN8it9+t0St3Ep0d2cfy5XAlhqpTzxDXYcs75zbQQIS2xqrpMLbYelQJeiF0Ov0R+5BJjLs68GnlPWAwTqX6ymqvmxzvV2NRB+9YYRYst8aY3peXG6bseojlA04pzDdH5N5P2zqt0OsGetwT2RRkkeHmIro/PxeIh0CV1HNjglBCRFoOaxHmAkrL2h2FS70SyKPB1VmwYxx6l6CGA==.
[6:05:12 - API] afcgsnfdkz2irjrn sent ?OTR:AAIRAAAAEFK6QkT80V5PhmKn6Uni0kUAAAHS2s0bRdqIpqeOGV/N/8KWZs2GbWIWlmrVxRwM6JNTvbfL6ZELwgNo6GSIdMTl8HHOcKwSyub9EXZZDj5sQOTzt2nqjRoFxUYl58iKB5mS9ekdwQ1beqYbbwFG/SHln7g09GD5VN5Cum7Q4hcS6ch0A9dttt3XMvxS0l+ieFoRUwYO3KJhXnVDpIctpsbeDZfGdUpUOs2h3bIQqIFk9SMJ2syg1WnoRsoyqX/mXo9ppT8ikbO2u33aoPABLpUjNJ+psqZR/ADAvVu57TTmjwzLlVvPS0Ubo8Edlwx92srEdK0ZctGD5y5pubbSJ64nckgxtSwiCUMsnfvSz21suCpTFdAC05tfMJE/mt0QYfVPg7wc1/yjdGD1WbaLLh1/OmDMMYAC2qSnGg6r7Yil1B8AJLwCzPo1S8sv44vYCEXxaLpem9U0XL3lzhONu7i4xbWbCNKYVM91x+Qr6OY2P0/K/b9t6OfZFGzSH56BsGyFyfOoy1X40Hk5hJ8a74t3+BvzagIhcJYGi6uJFcfLqqCEzJFLgjhgwav8C2L7LgHwP6BxSp4oqI0lkkQDdnIVQ9nb6kMupTyBt3rRyKxD9Lp2FKBWVqwA6aw3aeEg4RUEfpeOzY8j1HCDXYWaP6vbmVMdm1d4stzI.
[6:05:12 - OUT_OTR] From network:690: ?OTR:AAIRAAAAEFK6QkT80V5PhmKn6Uni0kUAAAHS2s0bRdqIpqeOGV/N/8KWZs2GbWIWlmrVxRwM6JNTvbfL6ZELwgNo6GSIdMTl8HHOcKwSyub9EXZZDj5sQOTzt2nqjRoFxUYl58iKB5mS9ekdwQ1beqYbbwFG/SHln7g09GD5VN5Cum7Q4hcS6ch0A9dttt3XMvxS0l+ieFoRUwYO3KJhXnVDpIctpsbeDZfGdUpUOs2h3bIQqIFk9SMJ2syg1WnoRsoyqX/mXo9ppT8ikbO2u33aoPABLpUjNJ+psqZR/ADAvVu57TTmjwzLlVvPS0Ubo8Edlwx92srEdK0ZctGD5y5pubbSJ64nckgxtSwiCUMsnfvSz21suCpTFdAC05tfMJE/mt0QYfVPg7wc1/yjdGD1WbaLLh1/OmDMMYAC2qSnGg6r7Yil1B8AJLwCzPo1S8sv44vYCEXxaLpem9U0XL3lzhONu7i4xbWbCNKYVM91x+Qr6OY2P0/K/b9t6OfZFGzSH56BsGyFyfOoy1X40Hk5hJ8a74t3+BvzagIhcJYGi6uJFcfLqqCEzJFLgjhgwav8C2L7LgHwP6BxSp4oqI0lkkQDdnIVQ9nb6kMupTyBt3rRyKxD9Lp2FKBWVqwA6aw3aeEg4RUEfpeOzY8j1HCDXYWaP6vbmVMdm1d4stzI.

[6:05:13 - java.lang.Class] New fingerprint is created.5DED25F0A17A5D6CBB55A87369E04023ABBCA6CF
[6:05:13 - java.lang.Class] Writing fingerprints.
[6:05:13 - core.Buddy] Send afcgsnfdkz2irjrn status available
[6:05:13 - java.lang.Class] Updating context list.
[6:05:13 - java.lang.Class] AKE succeeded

[6:05:13 - java.lang.Class] Injecting message to the recipient:666: ?OTR:AAISAAAB0q/DA/7zaERmmLSi16HcWHH2kvZyUpmKtSgZJszqqA1WnL9oHk1kzA17wAk/eP+vV4t+7i8G+YjvgXFSv1UYi9uAawqRYk79Xgd69cIe68zu/oulme0dAkACP/idz2vJKh4ZZsIlGSOzsLtxw+k6HreEaE5G8Ly9G6D/DTm74Gng9rrW3Oo1ch1dhI2hQ3UmZpKjE/HZ/p6PMzBoG67M/pXgTPajbWddGZzqAVVlgTud2tl3eNouRd90VMO+TdNwwmpxI0/Ibc2hCYXfgfOUSDjoLnMVLzYPbmppFgHgynNzWO9bHxTcs0+1BesarKfKNqOooAdyMk1A3+I8yamOCEETIih+bfAZhOxkocbYbCVXjkrVr5WblLxpUhNv+Dxs+T6mUuukFHPB48Uk8acjJ+dq+8WFEYZZL/Vi8yS8DtxjTmIq7GQP8awnOufCdSOQ4gb8B3QHydUNJVlLF9Ct8UeIgqjYqdwdFgi0eAVk1YSFA3FX+KoO+V6/+1q2nOyR1vfWER8QoxpD3m/mLc5HhgVnjRegjNU+5ytICi4iTmDBXUvUv+e7LQLBg3jMDYpp8VyKVYUYp+0OtInYIoZHhiqkzd50bpMRBbkMnc4azExe1/eP/co6VQUz45IaeiCMFG4SZOgoFQ==.
[6:05:13 - core.Buddy] Send afcgsnfdkz2irjrn message ?OTR:AAISAAAB0q/DA/7zaERmmLSi16HcWHH2kvZyUpmKtSgZJszqqA1WnL9oHk1kzA17wAk/eP+vV4t+7i8G+YjvgXFSv1UYi9uAawqRYk79Xgd69cIe68zu/oulme0dAkACP/idz2vJKh4ZZsIlGSOzsLtxw+k6HreEaE5G8Ly9G6D/DTm74Gng9rrW3Oo1ch1dhI2hQ3UmZpKjE/HZ/p6PMzBoG67M/pXgTPajbWddGZzqAVVlgTud2tl3eNouRd90VMO+TdNwwmpxI0/Ibc2hCYXfgfOUSDjoLnMVLzYPbmppFgHgynNzWO9bHxTcs0+1BesarKfKNqOooAdyMk1A3+I8yamOCEETIih+bfAZhOxkocbYbCVXjkrVr5WblLxpUhNv+Dxs+T6mUuukFHPB48Uk8acjJ+dq+8WFEYZZL/Vi8yS8DtxjTmIq7GQP8awnOufCdSOQ4gb8B3QHydUNJVlLF9Ct8UeIgqjYqdwdFgi0eAVk1YSFA3FX+KoO+V6/+1q2nOyR1vfWER8QoxpD3m/mLc5HhgVnjRegjNU+5ytICi4iTmDBXUvUv+e7LQLBg3jMDYpp8VyKVYUYp+0OtInYIoZHhiqkzd50bpMRBbkMnc4azExe1/eP/co6VQUz45IaeiCMFG4SZOgoFQ==.
[6:05:26 - IN_OTR] Converting to OTR:5:hello
[6:05:26 - java.lang.Class] Injecting message to the recipient:346: ?OTR:AAIDAAAAAAEAAAABAAAAwEu36ZTujFISElhN1j0pI2vMd4qW3Gdr8i5oc+lvGOoNBT8NSIV/PCqOr6/1l9g9R0htv2fbED02yVSVHHLG6BiPtmxkBqm4eRRy1FS4C9wPVwTBmUVofZiD5DSQAIrZ/qzafwchFBRqCYhTAelbMa1AFGV24EotEKanHlP2CVFXaNKTmujJTB0USNeWmqkuBKtIZe1BUOJfoiTFXWXWcRK3cY87fzN7H7Dsi5WANaxBDW0AekFm4zJVNlvALMqoKAAAAAAAAAABAAAACyifzAYcmW0CN5XOgfC3nvGJiGr5fQzy+cghk98d1+QAAAAA.
[6:05:26 - core.Buddy] Send afcgsnfdkz2irjrn message ?OTR:AAIDAAAAAAEAAAABAAAAwEu36ZTujFISElhN1j0pI2vMd4qW3Gdr8i5oc+lvGOoNBT8NSIV/PCqOr6/1l9g9R0htv2fbED02yVSVHHLG6BiPtmxkBqm4eRRy1FS4C9wPVwTBmUVofZiD5DSQAIrZ/qzafwchFBRqCYhTAelbMa1AFGV24EotEKanHlP2CVFXaNKTmujJTB0USNeWmqkuBKtIZe1BUOJfoiTFXWXWcRK3cY87fzN7H7Dsi5WANaxBDW0AekFm4zJVNlvALMqoKAAAAAAAAAABAAAACyifzAYcmW0CN5XOgfC3nvGJiGr5fQzy+cghk98d1+QAAAAA.
[6:05:26 - IN_OTR] Null received, maybe OTR control message
[6:05:28 - core.Buddy] Send afcgsnfdkz2irjrn status available
[6:05:41 - API] afcgsnfdkz2irjrn sent ?OTR:AAIDAAAAAAEAAAACAAAAwJsbYqOD5ilzCz+bEF7b0CZrdoRiGbviXGKZEXs6jgyezwsVqV+gsGSF1SSocJRrfayIN4dyOyvgiwTjY2npNCKirpAhi0NJhkr6LqIPLHSHsxP5s923RVCzzcmSUgs5JJXWPteHD4G9LxNeYBguSeaxK0tF7UZpo28RAQD7PlWt6ZGbQC0kSUZkcNP0+JRIgjSoWaWMWhVLSgCyFdH9EIQo4Oo+QJqNkkGgvRVJmjlZ+exgQLi/GRRhxHUE0n1NKQAAAAAAAAABAAAAEnDv8K226zxIDie0G87NixojXjIi8GBdO+Rcx9UwcpnRtOpn6d3gAAAAAA==.
[6:05:41 - OUT_OTR] From network:358: ?OTR:AAIDAAAAAAEAAAACAAAAwJsbYqOD5ilzCz+bEF7b0CZrdoRiGbviXGKZEXs6jgyezwsVqV+gsGSF1SSocJRrfayIN4dyOyvgiwTjY2npNCKirpAhi0NJhkr6LqIPLHSHsxP5s923RVCzzcmSUgs5JJXWPteHD4G9LxNeYBguSeaxK0tF7UZpo28RAQD7PlWt6ZGbQC0kSUZkcNP0+JRIgjSoWaWMWhVLSgCyFdH9EIQo4Oo+QJqNkkGgvRVJmjlZ+exgQLi/GRRhxHUE0n1NKQAAAAAAAAABAAAAEnDv8K226zxIDie0G87NixojXjIi8GBdO+Rcx9UwcpnRtOpn6d3gAAAAAA==.
[6:05:41 - OUT_OTR] From OTR:17: /otr how are you?
[6:05:43 - API] afcgsnfdkz2irjrn sent ?OTR:AAIDAAAAAAEAAAACAAAAwJsbYqOD5ilzCz+bEF7b0CZrdoRiGbviXGKZEXs6jgyezwsVqV+gsGSF1SSocJRrfayIN4dyOyvgiwTjY2npNCKirpAhi0NJhkr6LqIPLHSHsxP5s923RVCzzcmSUgs5JJXWPteHD4G9LxNeYBguSeaxK0tF7UZpo28RAQD7PlWt6ZGbQC0kSUZkcNP0+JRIgjSoWaWMWhVLSgCyFdH9EIQo4Oo+QJqNkkGgvRVJmjlZ+exgQLi/GRRhxHUE0n1NKQAAAAAAAAACAAAAEvY5Ueh3XfZtJ0RqvfJSOyoeWmHs4y7H/uu2nCu6rj/3dsB8yAVCAAAAAA==.
[6:05:43 - OUT_OTR] From network:358: ?OTR:AAIDAAAAAAEAAAACAAAAwJsbYqOD5ilzCz+bEF7b0CZrdoRiGbviXGKZEXs6jgyezwsVqV+gsGSF1SSocJRrfayIN4dyOyvgiwTjY2npNCKirpAhi0NJhkr6LqIPLHSHsxP5s923RVCzzcmSUgs5JJXWPteHD4G9LxNeYBguSeaxK0tF7UZpo28RAQD7PlWt6ZGbQC0kSUZkcNP0+JRIgjSoWaWMWhVLSgCyFdH9EIQo4Oo+QJqNkkGgvRVJmjlZ+exgQLi/GRRhxHUE0n1NKQAAAAAAAAACAAAAEvY5Ueh3XfZtJ0RqvfJSOyoeWmHs4y7H/uu2nCu6rj/3dsB8yAVCAAAAAA==.
</pre>
