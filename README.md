# springSecurityRest
 这是一个值得学习记录的学习代码，主要是实现了基于mysql数据库实现了Spring Security保护REST API，以下文章为转载，代码完全对不上，但是基本流程是一样的，我有时间了之后会慢慢修改下文为这个仓库代码的说明文章。
 
# 重拾后端之Spring Boot（四）：使用JWT和Spring Security保护REST API

通常情况下，把API直接暴露出去是风险很大的，不说别的，直接被机器攻击就喝一壶的。那么一般来说，对API要划分出一定的权限级别，然后做一个用户的鉴权，依据鉴权结果给予用户开放对应的API。目前，比较主流的方案有几种:

 1. 用户名和密码鉴权，使用Session保存用户鉴权结果。
 2. 使用OAuth进行鉴权（其实OAuth也是一种基于Token的鉴权，只是没有规定Token的生成方式） 
 3. 自行采用Token进行鉴权

第一种就不介绍了，由于依赖Session来维护状态，也不太适合移动时代，新的项目就不要采用了。第二种OAuth的方案和JWT都是基于Token的，但OAuth其实对于不做开放平台的公司有些过于复杂。我们主要介绍第三种：JWT。

## 什么是JWT？

JWT是 `Json Web Token` 的缩写。它是基于 [RFC 7519][17] 标准定义的一种可以安全传输的 **小巧** 和 **自包含** 的JSON对象。由于数据是使用数字签名的，所以是可信任的和安全的。JWT可以使用HMAC算法对secret进行加密或者使用RSA的公钥私钥对来进行签名。

### JWT的工作流程

下面是一个JWT的工作流程图。模拟一下实际的流程是这样的（假设受保护的API在`/protected`中）

 1. 用户导航到登录页，输入用户名、密码，进行登录
 2. 服务器验证登录鉴权，如果改用户合法，根据用户的信息和服务器的规则生成JWT Token
 3. 服务器将该token以json形式返回（不一定要json形式，这里说的是一种常见的做法）
 4. 用户得到token，存在localStorage、cookie或其它数据存储形式中。
 5. 以后用户请求`/protected`中的API时，在请求的header中加入 `Authorization: Bearer xxxx(token)`。此处注意token之前有一个7字符长度的 `Bearer `
 6. 服务器端对此token进行检验，如果合法就解析其中内容，根据其拥有的权限和自己的业务逻辑给出对应的响应结果。
 7. 用户取得结果

![JWT工作流程图][18]

为了更好的理解这个token是什么，我们先来看一个token生成后的样子，下面那坨乱糟糟的就是了。

```
eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ3YW5nIiwiY3JlYXRlZCI6MTQ4OTA3OTk4MTM5MywiZXhwIjoxNDg5Njg0NzgxfQ.RC-BYCe_UZ2URtWddUpWXIp4NMsoeq2O6UF-8tVplqXY1-CI9u1-a-9DAAJGfNWkHE81mpnR3gXzfrBAB3WUAg
```

但仔细看到的话还是可以看到这个token分成了三部分，每部分用 `.` 分隔，每段都是用 [Base64][19] 编码的。如果我们用一个Base64的解码器的话 （ https://www.base64decode.org/ ），可以看到第一部分 `eyJhbGciOiJIUzUxMiJ9` 被解析成了: 

```
{
    "alg":"HS512"
}

```

这是告诉我们HMAC采用HS512算法对JWT进行的签名。

第二部分 `eyJzdWIiOiJ3YW5nIiwiY3JlYXRlZCI6MTQ4OTA3OTk4MTM5MywiZXhwIjoxNDg5Njg0NzgxfQ` 被解码之后是 

```json
{
    "sub":"wang",
    "created":1489079981393,
    "exp":1489684781
}

```

这段告诉我们这个Token中含有的数据声明（Claim），这个例子里面有三个声明：`sub`, `created` 和 `exp`。在我们这个例子中，分别代表着用户名、创建时间和过期时间，当然你可以把任意数据声明在这里。

看到这里，你可能会想这是个什么鬼token，所有信息都透明啊，安全怎么保障？别急，我们看看token的第三段 `RC-BYCe_UZ2URtWddUpWXIp4NMsoeq2O6UF-8tVplqXY1-CI9u1-a-9DAAJGfNWkHE81mpnR3gXzfrBAB3WUAg`。同样使用Base64解码之后，咦，这是什么东东

```
D X	DmYTeȧLUZcPZ0$gZAY_7wY@ 
```

最后一段其实是签名，这个签名必须知道秘钥才能计算。这个也是JWT的安全保障。这里提一点注意事项，由于数据声明（Claim）是公开的，千万不要把密码等敏感字段放进去，否则就等于是公开给别人了。

也就是说JWT是由三段组成的，按官方的叫法分别是header（头）、payload（负载）和signature（签名）：

```
header.payload.signature
```

头中的数据通常包含两部分：一个是我们刚刚看到的 `alg`，这个词是 `algorithm` 的缩写，就是指明算法。另一个可以添加的字段是token的类型(按RFC 7519实现的token机制不只JWT一种)，但如果我们采用的是JWT的话，指定这个就多余了。

```
{
  "alg": "HS512",
  "typ": "JWT"
}
```

payload中可以放置三类数据：系统保留的、公共的和私有的：

 - 系统保留的声明（Reserved claims）：这类声明不是必须的，但是是建议使用的，包括：iss (签发者), exp (过期时间),
   sub (主题), aud (目标受众)等。这里我们发现都用的缩写的三个字符，这是由于JWT的目标就是尽可能小巧。
 - 公共声明：这类声明需要在 [IANA JSON Web Token Registry][20] 中定义或者提供一个URI，因为要避免重名等冲突。
 - 私有声明：这个就是你根据业务需要自己定义的数据了。

签名的过程是这样的：采用header中声明的算法，接受三个参数：base64编码的header、base64编码的payload和秘钥（secret）进行运算。签名这一部分如果你愿意的话，可以采用RSASHA256的方式进行公钥、私钥对的方式进行，如果安全性要求的高的话。

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

### JWT的生成和解析

为了简化我们的工作，这里引入一个比较成熟的JWT类库，叫 `jjwt` ( https://github.com/jwtk/jjwt )。这个类库可以用于Java和Android的JWT token的生成和验证。

JWT的生成可以使用下面这样的代码完成：

```java
String generateToken(Map<String, Object> claims) {
    return Jwts.builder()
            .setClaims(claims)
            .setExpiration(generateExpirationDate())
            .signWith(SignatureAlgorithm.HS512, secret) //采用什么算法是可以自己选择的，不一定非要采用HS512
            .compact();
}
```

数据声明（Claim）其实就是一个Map，比如我们想放入用户名，可以简单的创建一个Map然后put进去就可以了。

```java
Map<String, Object> claims = new HashMap<>();
claims.put(CLAIM_KEY_USERNAME, username());
```

解析也很简单，利用 `jjwt` 提供的parser传入秘钥，然后就可以解析token了。

```java
Claims getClaimsFromToken(String token) {
    Claims claims;
    try {
        claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    } catch (Exception e) {
        claims = null;
    }
    return claims;
}
```

JWT本身没啥难度，但安全整体是一个比较复杂的事情，JWT只不过提供了一种基于token的请求验证机制。但我们的用户权限，对于API的权限划分、资源的权限划分，用户的验证等等都不是JWT负责的。也就是说，请求验证后，你是否有权限看对应的内容是由你的用户角色决定的。所以我们这里要利用Spring的一个子项目Spring Security来简化我们的工作。

## Spring Security

Spring Security是一个基于Spring的通用安全框架，里面内容太多了，本文的主要目的也不是展开讲这个框架，而是如何利用Spring Security和JWT一起来完成API保护。所以关于Spring Secruity的基础内容或展开内容，请自行去官网学习（ http://projects.spring.io/spring-security/ ）。

### 简单的背景知识

如果你的系统有用户的概念的话，一般来说，你应该有一个用户表，最简单的用户表，应该有三列：Id，Username和Password，类似下表这种

| ID | USERNAME | PASSWORD |
|----|----------|----------|
| 10 | wang | abcdefg |

而且不是所有用户都是一种角色，比如网站管理员、供应商、财务等等，这些角色和网站的直接用户需要的权限可能是不一样的。那么我们就需要一个角色表：

| ID | ROLE | 
|----|------|
| 10 | USER |
| 20 | ADMIN |

当然我们还需要一个可以将用户和角色关联起来建立映射关系的表。

| USER_ID | ROLE_ID | 
|----|------|
| 10 | 10 |
| 20 | 20 |

这是典型的一个关系型数据库的用户角色的设计，由于我们要使用的MongoDB是一个文档型数据库，所以让我们重新审视一下这个结构。

这个数据结构的优点在于它避免了数据的冗余，每个表负责自己的数据，通过关联表进行关系的描述，同时也保证的数据的完整性：比如当你修改角色名称后，没有脏数据的产生。

但是这种事情在用户权限这个领域发生的频率到底有多少呢？有多少人每天不停的改的角色名称？当然如果你的业务场景确实是需要保证数据完整性，你还是应该使用关系型数据库。但如果没有高频的对于角色表的改动，其实我们是不需要这样的一个设计的。在MongoDB中我们可以将其简化为

```json
{
  _id: <id_generated>
  username: 'user',
  password: 'pass',
  roles: ['USER', 'ADMIN']
}
```

基于以上考虑，我们重构一下 `User` 类，

```java
@Data
public class User {
    @Id
    private String id;

    @Indexed(unique=true, direction= IndexDirection.DESCENDING, dropDups=true)
    private String username;

    private String password;
    private String email;
    private Date lastPasswordResetDate;
    private List<String> roles;
}
```

当然你可能发现这个类有点怪，只有一些field，这个简化的能力是一个叫`lombok`类库提供的 ，这个很多开发过Android的童鞋应该熟悉，是用来简化POJO的创建的一个类库。简单说一下，采用 `lombok` 提供的 `@Data` 修饰符后可以简写成，原来的一坨getter和setter以及constructor等都不需要写了。类似的 `Todo` 可以改写成：

```java
@Data
public class Todo {
    @Id private String id;
    private String desc;
    private boolean completed;
    private User user;
}
```

增加这个类库只需在 `build.gradle` 中增加下面这行

```gradle
dependencies {
	// 省略其它依赖
    compile("org.projectlombok:lombok:${lombokVersion}")
}
```

### 引入Spring Security

要在Spring Boot中引入Spring Security非常简单，修改 `build.gradle`，增加一个引用 `org.springframework.boot:spring-boot-starter-security`：

```gradle
dependencies {
	compile("org.springframework.boot:spring-boot-starter-data-rest")
	compile("org.springframework.boot:spring-boot-starter-data-mongodb")
	compile("org.springframework.boot:spring-boot-starter-security")
	compile("io.jsonwebtoken:jjwt:${jjwtVersion}")
    compile("org.projectlombok:lombok:${lombokVersion}")
	testCompile("org.springframework.boot:spring-boot-starter-test")
}
```

你可能发现了，我们不只增加了对Spring Security的编译依赖，还增加 `jjwt` 的依赖。

Spring Security需要我们实现几个东西，第一个是UserDetails：这个接口中规定了用户的几个必须要有的方法，所以我们创建一个JwtUser类来实现这个接口。为什么不直接使用User类？因为这个UserDetails完全是为了安全服务的，它和我们的领域类可能有部分属性重叠，但很多的接口其实是安全定制的，所以最好新建一个类：

```java
public class JwtUser implements UserDetails {
    private final String id;
    private final String username;
    private final String password;
    private final String email;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Date lastPasswordResetDate;

    public JwtUser(
            String id,
            String username,
            String password,
            String email,
            Collection<? extends GrantedAuthority> authorities,
            Date lastPasswordResetDate) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.authorities = authorities;
        this.lastPasswordResetDate = lastPasswordResetDate;
    }
    //返回分配给用户的角色列表
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    @JsonIgnore
    public String getId() {
        return id;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }
    // 账户是否未过期
    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    // 账户是否未锁定
    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    // 密码是否未过期
    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    // 账户是否激活
    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }
    // 这个是自定义的，返回上次密码重置日期
    @JsonIgnore
    public Date getLastPasswordResetDate() {
        return lastPasswordResetDate;
    }
}
```

这个接口中规定的很多方法我们都简单粗暴的设成直接返回某个值了，这是为了简单起见，你在实际开发环境中还是要根据具体业务调整。当然由于两个类还是有一定关系的，为了写起来简单，我们写一个工厂类来由领域对象创建 `JwtUser`，这个工厂就叫 `JwtUserFactory` 吧：

```java
public final class JwtUserFactory {

    private JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                mapToGrantedAuthorities(user.getRoles()),
                user.getLastPasswordResetDate()
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthorities(List<String> authorities) {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
```


第二个要实现的是 `UserDetailsService`，这个接口只定义了一个方法 `loadUserByUsername`，顾名思义，就是提供一种从用户名可以查到用户并返回的方法。注意，不一定是数据库哦，文本文件、xml文件等等都可能成为数据源，这也是为什么Spring提供这样一个接口的原因：保证你可以采用灵活的数据源。接下来我们建立一个 `JwtUserDetailsServiceImpl` 来实现这个接口。

```java
@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return JwtUserFactory.create(user);
        }
    }
}

```

为了让Spring可以知道我们想怎样控制安全性，我们还需要建立一个安全配置类 `WebSecurityConfig`：

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    // Spring会自动寻找同样类型的具体类注入，这里就是JwtUserDetailsServiceImpl了
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                // 设置UserDetailsService
                .userDetailsService(this.userDetailsService)
                // 使用BCrypt进行密码的hash
                .passwordEncoder(passwordEncoder());
    }
    // 装载BCrypt密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 由于使用的是JWT，我们这里不需要csrf
                .csrf().disable()

                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

                .authorizeRequests()
                //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // 允许对于网站静态资源的无授权访问
                .antMatchers(
                        HttpMethod.GET,
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll()
                // 对于获取token的rest api要允许匿名访问
                .antMatchers("/auth/**").permitAll()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();

        // 禁用缓存
        httpSecurity.headers().cacheControl();
    }
}
```

接下来我们要规定一下哪些资源需要什么样的角色可以访问了，在 `UserController` 加一个修饰符 `@PreAuthorize("hasRole('ADMIN')")` 表示这个资源只能被拥有 `ADMIN` 角色的用户访问。

```java
/**
 * 在 @PreAuthorize 中我们可以利用内建的 SPEL 表达式：比如 'hasRole()' 来决定哪些用户有权访问。
 * 需注意的一点是 hasRole 表达式认为每个角色名字前都有一个前缀 'ROLE_'。所以这里的 'ADMIN' 其实在
 * 数据库中存储的是 'ROLE_ADMIN' 。这个 @PreAuthorize 可以修饰Controller也可修饰Controller中的方法。
 **/
@RestController
@RequestMapping("/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {
    @Autowired
    private UserRepository repository;

    @RequestMapping(method = RequestMethod.GET)
    public List<User> getUsers() {
        return repository.findAll();
    }

    // 略去其它部分
}
```

类似的我们给 `TodoController` 加上 `@PreAuthorize("hasRole('USER')")`，标明这个资源只能被拥有 `USER` 角色的用户访问：

```java
@RestController
@RequestMapping("/todos")
@PreAuthorize("hasRole('USER')")
public class TodoController {
    // 略去
}
```

### 使用application.yml配置SpringBoot应用

现在应该Spring Security可以工作了，但为了可以更清晰的看到工作日志，我们希望配置一下，在和 `src` 同级建立一个config文件夹，在这个文件夹下面新建一个 `application.yml`。

```yml
# Server configuration
server:
  port: 8090
  contextPath:

# Spring configuration
spring:
  jackson:
    serialization:
      INDENT_OUTPUT: true
  data.mongodb:
    host: localhost
    port: 27017
    database: springboot

# Logging configuration
logging:
  level:
    org.springframework:
      data: DEBUG
      security: DEBUG

```

我们除了配置了logging的一些东东外，也顺手设置了数据库和http服务的一些配置项，现在我们的服务器会在8090端口监听，而spring data和security的日志在debug模式下会输出到console。

现在启动服务后，访问 `http://localhost:8090` 你可以看到根目录还是正常显示的

![根目录还是正常可以访问的][21]

但我们试一下 `http://localhost:8090/users` ，观察一下console，我们会看到如下的输出，告诉由于用户未鉴权，我们访问被拒绝了。

```
2017-03-10 15:51:53.351 DEBUG 57599 --- [nio-8090-exec-4] o.s.s.w.a.ExceptionTranslationFilter     : Access is denied (user is anonymous); redirecting to authentication entry point

org.springframework.security.access.AccessDeniedException: Access is denied
	at org.springframework.security.access.vote.AffirmativeBased.decide(AffirmativeBased.java:84) ~[spring-security-core-4.2.1.RELEASE.jar:4.2.1.RELEASE]
```

## 集成JWT和Spring Security

到现在，我们还是让JWT和Spring Security各自为战，并没有集成起来。要想要JWT在Spring中工作，我们应该新建一个filter，并把它配置在 `WebSecurityConfig` 中。

```java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Value("${jwt.header}")
    private String tokenHeader;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(tokenHead)) {
            final String authToken = authHeader.substring(tokenHead.length()); // The part after "Bearer "
            String username = jwtTokenUtil.getUsernameFromToken(authToken);

            logger.info("checking authentication " + username);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(
                            request));
                    logger.info("authenticated user " + username + ", setting security context");
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        chain.doFilter(request, response);
    }
}
```

事实上如果我们足够相信token中的数据，也就是我们足够相信签名token的secret的机制足够好，这种情况下，我们可以不用再查询数据库，而直接采用token中的数据。本例中，我们还是通过Spring Security的 `@UserDetailsService` 进行了数据查询，但简单验证的话，你可以采用直接验证token是否合法来避免昂贵的数据查询。

接下来，我们会在 `WebSecurityConfig` 中注入这个filter，并且配置到 `HttpSecurity` 中：

```java
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    // 省略其它部分

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        // 省略之前写的规则部分，具体看前面的代码

        // 添加JWT filter
        httpSecurity
                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
    }
}
```

### 完成鉴权（登录）、注册和更新token的功能

到现在，我们整个API其实已经在安全的保护下了，但我们遇到一个问题：所有的API都安全了，但我们还没有用户啊，所以所有API都没法访问。因此要提供一个注册、登录的API，这个API应该是可以匿名访问的。给它规划的路径呢，我们前面其实在`WebSecurityConfig`中已经给出了，就是 `/auth`。

首先需要一个AuthService，规定一下必选动作：

```java
public interface AuthService {
    User register(User userToAdd);
    String login(String username, String password);
    String refresh(String oldToken);
}
```

然后，实现这些必选动作，其实非常简单：

1. 登录时要生成token，完成Spring Security认证，然后返回token给客户端
2. 注册时将用户密码用BCrypt加密，写入用户角色，由于是开放注册，所以写入角色系统控制，将其写成 `ROLE_USER`
3. 提供一个可以刷新token的接口 refresh 用于取得新的token

```java
@Service
public class AuthServiceImpl implements AuthService {

    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;
    private JwtTokenUtil jwtTokenUtil;
    private UserRepository userRepository;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Autowired
    public AuthServiceImpl(
            AuthenticationManager authenticationManager,
            UserDetailsService userDetailsService,
            JwtTokenUtil jwtTokenUtil,
            UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
    }

    @Override
    public User register(User userToAdd) {
        final String username = userToAdd.getUsername();
        if(userRepository.findByUsername(username)!=null) {
            return null;
        }
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        final String rawPassword = userToAdd.getPassword();
        userToAdd.setPassword(encoder.encode(rawPassword));
        userToAdd.setLastPasswordResetDate(new Date());
        userToAdd.setRoles(asList("ROLE_USER"));
        return userRepository.insert(userToAdd);
    }

    @Override
    public String login(String username, String password) {
        UsernamePasswordAuthenticationToken upToken = new UsernamePasswordAuthenticationToken(username, password);
        final Authentication authentication = authenticationManager.authenticate(upToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        final String token = jwtTokenUtil.generateToken(userDetails);
        return token;
    }

    @Override
    public String refresh(String oldToken) {
        final String token = oldToken.substring(tokenHead.length());
        String username = jwtTokenUtil.getUsernameFromToken(token);
        JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);
        if (jwtTokenUtil.canTokenBeRefreshed(token, user.getLastPasswordResetDate())){
            return jwtTokenUtil.refreshToken(token);
        }
        return null;
    }
}
```

然后建立AuthController就好，这个AuthController中我们在其中使用了表达式绑定，比如 `@Value("${jwt.header}")`中的 `jwt.header` 其实是定义在 `applicaiton.yml` 中的

```yml
# JWT
jwt:
  header: Authorization
  secret: mySecret
  expiration: 604800
  tokenHead: "Bearer "
  route:
    authentication:
      path: auth
      refresh: refresh
      register: "auth/register"
```

同样的 `@RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)` 中的 `jwt.route.authentication.path` 也是定义在上面的

```java
@RestController
public class AuthController {
    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthService authService;

    @RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(
            @RequestBody JwtAuthenticationRequest authenticationRequest) throws AuthenticationException{
        final String token = authService.login(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        // Return the token
        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }

    @RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.GET)
    public ResponseEntity<?> refreshAndGetAuthenticationToken(
            HttpServletRequest request) throws AuthenticationException{
        String token = request.getHeader(tokenHeader);
        String refreshedToken = authService.refresh(token);
        if(refreshedToken == null) {
            return ResponseEntity.badRequest().body(null);
        } else {
            return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken));
        }
    }

    @RequestMapping(value = "${jwt.route.authentication.register}", method = RequestMethod.POST)
    public User register(@RequestBody User addedUser) throws AuthenticationException{
        return authService.register(addedUser);
    }
}
```

## 验证时间

接下来，我们就可以看看我们的成果了，首先注册一个用户 `peng2`，很完美的注册成功了

![注册用户][22]

然后在 `/auth` 中取得token，也很成功

![取得token][23]

不使用token时，访问 `/users` 的结果，不出意料的失败，提示未授权。

![不使用token访问users列表][24]

使用token时，访问 `/users` 的结果，虽然仍是失败，但这次提示访问被拒绝，意思就是虽然你已经得到了授权，但由于你的会员级别还只是普卡会员，所以你的请求被拒绝。

![image_1bas22va52vk1rj445fhm87k72a.png-156.9kB][25]

接下来我们访问 `/users/?username=peng2`，竟然可以访问啊

![访问自己的信息是允许的][26]

这是由于我们为这个方法定义的权限就是：拥有ADMIN角色或者是当前用户本身。Spring Security真是很方便，很强大。

```java
@PostAuthorize("returnObject.username == principal.username or hasRole('ROLE_ADMIN')")
    @RequestMapping(value = "/",method = RequestMethod.GET)
    public User getUserByUsername(@RequestParam(value="username") String username) {
        return repository.findByUsername(username);
    }
```
