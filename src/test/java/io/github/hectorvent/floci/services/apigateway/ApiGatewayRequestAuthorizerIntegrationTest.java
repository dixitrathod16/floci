package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.AuthorizerType;
import software.amazon.awssdk.services.apigateway.model.CreateAuthorizerRequest;
import software.amazon.awssdk.services.apigateway.model.CreateDeploymentRequest;
import software.amazon.awssdk.services.apigateway.model.CreateResourceRequest;
import software.amazon.awssdk.services.apigateway.model.CreateRestApiRequest;
import software.amazon.awssdk.services.apigateway.model.CreateStageRequest;
import software.amazon.awssdk.services.apigateway.model.DeleteRestApiRequest;
import software.amazon.awssdk.services.apigateway.model.GetResourcesRequest;
import software.amazon.awssdk.services.apigateway.model.IntegrationType;
import software.amazon.awssdk.services.apigateway.model.PutIntegrationRequest;
import software.amazon.awssdk.services.apigateway.model.PutMethodRequest;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for REQUEST authorizer full event shape (issue #807).
 *
 * <p>Validates that {@code toAuthorizerEvent} populates the complete
 * {@code APIGatewayRequestAuthorizerEvent} shape for REQUEST-type authorizers,
 * and that TOKEN and NONE authorizer paths are unaffected.
 *
 * <p>Management-plane setup uses the AWS SDK v2 {@link ApiGatewayClient}.
 * Lambda functions are created via the Lambda REST API (no SDK dep needed in main pom).
 * Execute-api invocations use RestAssured against the local Floci endpoint.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewayRequestAuthorizerIntegrationTest {

    @TestHTTPResource("/")
    URI baseUri;

    private static final String LAMBDA_BASE_PATH = "/2015-03-31/functions";
    private static final String AUTHORIZER_FUNCTION = "apigw-request-auth-echo";
    private static final String PROXY_FUNCTION = "apigw-request-auth-proxy";
    private static final String TOKEN_AUTHORIZER_FUNCTION = "apigw-token-auth-echo";
    private static final String TOKEN_PROXY_FUNCTION = "apigw-token-auth-proxy";
    private static final String NONE_INTEGRATION_FUNCTION = "apigw-none-auth-integration";
    private static final String DENY_AUTHORIZER_FUNCTION = "apigw-deny-auth";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-role";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Shared SDK client — pointed at the local Floci instance
    private ApiGatewayClient gw;

    // State shared across ordered tests
    private String apiId;
    private String itemResourceId;
    private String authorizerId;

    private String tokenApiId;
    private String noneApiId;
    private String denyApiId;

    @BeforeAll
    void setUpClient() {
        gw = ApiGatewayClient.builder()
                .endpointOverride(baseUri)
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();
    }

    @AfterAll
    void tearDownClient() {
        if (gw != null) gw.close();
    }

    // ──────────────────────────── Lambda setup (raw HTTP — no Lambda SDK in main pom) ────────────────────────────

    @Test
    @Order(1)
    void createEchoAuthorizerLambda() throws Exception {
        createNodeLambda(AUTHORIZER_FUNCTION, """
                exports.handler = async (event) => ({
                  principalId: "test-user",
                  policyDocument: {
                    Version: "2012-10-17",
                    Statement: [{
                      Action: "execute-api:Invoke",
                      Effect: "Allow",
                      Resource: event.methodArn
                    }]
                  },
                  context: {
                    receivedEvent: JSON.stringify(event)
                  }
                });
                """);
    }

    @Test
    @Order(2)
    void createProxyLambda() throws Exception {
        createNodeLambda(PROXY_FUNCTION, """
                exports.handler = async (event) => ({
                  statusCode: 200,
                  body: JSON.stringify({
                    authorizer: event.requestContext && event.requestContext.authorizer
                      ? event.requestContext.authorizer
                      : null
                  })
                });
                """);
    }

    // ──────────────────────────── REQUEST authorizer API setup (SDK v2) ────────────────────────────

    @Test
    @Order(3)
    void createRestApi() {
        var api = gw.createRestApi(CreateRestApiRequest.builder()
                .name("request-authorizer-test-api")
                .build());
        apiId = api.id();
        assertNotNull(apiId);
    }

    @Test
    @Order(4)
    void createResources() {
        var resources = gw.getResources(GetResourcesRequest.builder()
                .restApiId(apiId)
                .build());
        String rootId = resources.items().get(0).id();

        var itemsRes = gw.createResource(CreateResourceRequest.builder()
                .restApiId(apiId)
                .parentId(rootId)
                .pathPart("items")
                .build());
        String itemsResourceId = itemsRes.id();

        var itemRes = gw.createResource(CreateResourceRequest.builder()
                .restApiId(apiId)
                .parentId(itemsResourceId)
                .pathPart("{id}")
                .build());
        itemResourceId = itemRes.id();
        assertNotNull(itemResourceId);
    }

    @Test
    @Order(5)
    void createRequestAuthorizer() {
        String authorizerUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + AUTHORIZER_FUNCTION + "/invocations";
        var auth = gw.createAuthorizer(CreateAuthorizerRequest.builder()
                .restApiId(apiId)
                .name("request-echo-authorizer")
                .type(AuthorizerType.REQUEST)
                .authorizerUri(authorizerUri)
                .identitySource("method.request.header.Authorization")
                .authorizerResultTtlInSeconds(0)
                .build());
        authorizerId = auth.id();
        assertNotNull(authorizerId);
    }

    @Test
    @Order(6)
    void configureMethodAndIntegration() {
        gw.putMethod(PutMethodRequest.builder()
                .restApiId(apiId)
                .resourceId(itemResourceId)
                .httpMethod("GET")
                .authorizationType("CUSTOM")
                .authorizerId(authorizerId)
                .build());

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + PROXY_FUNCTION + "/invocations";
        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(apiId)
                .resourceId(itemResourceId)
                .httpMethod("GET")
                .type(IntegrationType.AWS_PROXY)
                .integrationHttpMethod("POST")
                .uri(proxyUri)
                .build());
    }

    @Test
    @Order(7)
    void deployApi() {
        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(apiId)
                .description("request-auth-test")
                .build());
        gw.createStage(CreateStageRequest.builder()
                .restApiId(apiId)
                .stageName("prod")
                .deploymentId(dep.id())
                .build());
    }

    // ──────────────────────────── Core bug condition test ────────────────────────────

    /**
     * Validates that the REQUEST authorizer Lambda receives the full
     * {@code APIGatewayRequestAuthorizerEvent} shape: headers, queryStringParameters,
     * multiValueHeaders, multiValueQueryStringParameters, pathParameters, resource,
     * stageVariables, and requestContext (with requestId, identity.sourceIp, accountId, apiId).
     *
     * <p>On unfixed code this test fails because only {@code type} and {@code methodArn}
     * are populated.
     */
    @Test
    @Order(8)
    void requestAuthorizerReceivesFullEvent() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .when().get("/execute-api/" + apiId + "/prod/items/42?foo=bar")
                .then()
                .statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        JsonNode authorizer = payload.path("authorizer");

        assertFalse(authorizer.isNull(), "authorizer context should be present in proxy response");
        assertFalse(authorizer.isMissingNode(), "authorizer context should be present in proxy response");

        String receivedEventStr = authorizer.path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr, "authorizer should have embedded receivedEvent in context");
        assertFalse(receivedEventStr.isEmpty(), "receivedEvent should not be empty");

        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);

        // type and methodArn
        assertEquals("REQUEST", event.path("type").asText(null));
        assertFalse(event.path("methodArn").isMissingNode(), "methodArn must be present");
        assertTrue(event.path("methodArn").asText("").contains(apiId), "methodArn must contain apiId");

        // resource (matched template path) and actual path
        assertEquals("/items/{id}", event.path("resource").asText(null),
                "resource should be the matched resource path template");
        assertEquals("/items/42", event.path("path").asText(null),
                "path should be the actual request path");
        assertEquals("GET", event.path("httpMethod").asText(null));

        // headers
        assertFalse(event.path("headers").isNull(), "headers must be non-null");
        assertFalse(event.path("headers").isMissingNode(), "headers must be present");

        // multiValueHeaders
        assertFalse(event.path("multiValueHeaders").isNull(), "multiValueHeaders must be non-null");
        assertFalse(event.path("multiValueHeaders").isMissingNode(), "multiValueHeaders must be present");

        // queryStringParameters
        assertFalse(event.path("queryStringParameters").isNull(),
                "queryStringParameters must be non-null when query params are present");
        assertEquals("bar", event.path("queryStringParameters").path("foo").asText(null));

        // multiValueQueryStringParameters
        assertFalse(event.path("multiValueQueryStringParameters").isNull(),
                "multiValueQueryStringParameters must be non-null when query params are present");
        assertTrue(event.path("multiValueQueryStringParameters").path("foo").isArray());

        // pathParameters
        assertFalse(event.path("pathParameters").isNull(), "pathParameters must be non-null");
        assertEquals("42", event.path("pathParameters").path("id").asText(null));

        // stageVariables must be null (no stage variables configured)
        assertTrue(event.path("stageVariables").isNull(), "stageVariables must be null");

        // requestContext
        JsonNode ctx = event.path("requestContext");
        assertFalse(ctx.isNull(), "requestContext must be present");
        assertFalse(ctx.isMissingNode(), "requestContext must be present");

        String requestId = ctx.path("requestId").asText(null);
        assertNotNull(requestId, "requestContext.requestId must be non-null");
        assertFalse(requestId.isEmpty(), "requestContext.requestId must be non-empty");

        assertEquals("127.0.0.1", ctx.path("identity").path("sourceIp").asText(null),
                "requestContext.identity.sourceIp must equal '127.0.0.1'");
        // apiKey is null because no usage plan with a matching key is linked to this stage
        assertTrue(ctx.path("identity").path("apiKey").isNull(),
                "requestContext.identity.apiKey must be null when no matching usage plan key exists");
        assertEquals("/items/{id}", ctx.path("resourcePath").asText(null));
        assertEquals("/items/42", ctx.path("path").asText(null),
                "requestContext.path must equal the actual request path");
        assertEquals("GET", ctx.path("httpMethod").asText(null));
        assertEquals("prod", ctx.path("stage").asText(null));
        assertEquals(ACCOUNT, ctx.path("accountId").asText(null),
                "requestContext.accountId must be present");
        assertEquals(apiId, ctx.path("apiId").asText(null),
                "requestContext.apiId must be present");

        // resourceId is the actual resource ID assigned by Floci at creation time
        String resourceId = ctx.path("resourceId").asText(null);
        assertNotNull(resourceId, "requestContext.resourceId must be non-null");
        assertFalse(resourceId.isEmpty(), "requestContext.resourceId must be non-empty");
    }

    @Test
    @Order(9)
    void requestAuthorizerNullQueryParamsWhenNonePresent() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .when().get("/execute-api/" + apiId + "/prod/items/99")
                .then()
                .statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr);

        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);
        assertTrue(event.path("queryStringParameters").isNull(),
                "queryStringParameters must be null when no query string is present");
        assertTrue(event.path("multiValueQueryStringParameters").isNull(),
                "multiValueQueryStringParameters must be null when no query string is present");
    }

    // ──────────────────────────── TOKEN authorizer preservation ────────────────────────────

    @Test
    @Order(10)
    void preservation_createTokenLambdas() throws Exception {
        createNodeLambda(TOKEN_AUTHORIZER_FUNCTION, """
                exports.handler = async (event) => ({
                  principalId: "test-user",
                  policyDocument: {
                    Version: "2012-10-17",
                    Statement: [{
                      Action: "execute-api:Invoke",
                      Effect: "Allow",
                      Resource: event.methodArn
                    }]
                  },
                  context: {
                    receivedEvent: JSON.stringify(event)
                  }
                });
                """);
        createNodeLambda(TOKEN_PROXY_FUNCTION, """
                exports.handler = async (event) => ({
                  statusCode: 200,
                  body: JSON.stringify({
                    authorizer: event.requestContext && event.requestContext.authorizer
                      ? event.requestContext.authorizer
                      : null
                  })
                });
                """);
    }

    @Test
    @Order(11)
    void preservation_setupTokenAuthorizerApi() {
        var api = gw.createRestApi(CreateRestApiRequest.builder()
                .name("token-authorizer-preservation-api")
                .build());
        tokenApiId = api.id();

        var resources = gw.getResources(GetResourcesRequest.builder()
                .restApiId(tokenApiId)
                .build());
        String rootId = resources.items().get(0).id();

        var secureRes = gw.createResource(CreateResourceRequest.builder()
                .restApiId(tokenApiId)
                .parentId(rootId)
                .pathPart("secure")
                .build());
        String secureResourceId = secureRes.id();

        String authUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + TOKEN_AUTHORIZER_FUNCTION + "/invocations";
        var auth = gw.createAuthorizer(CreateAuthorizerRequest.builder()
                .restApiId(tokenApiId)
                .name("token-echo-authorizer")
                .type(AuthorizerType.TOKEN)
                .authorizerUri(authUri)
                .identitySource("method.request.header.Authorization")
                .authorizerResultTtlInSeconds(0)
                .build());

        gw.putMethod(PutMethodRequest.builder()
                .restApiId(tokenApiId)
                .resourceId(secureResourceId)
                .httpMethod("GET")
                .authorizationType("CUSTOM")
                .authorizerId(auth.id())
                .build());

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + TOKEN_PROXY_FUNCTION + "/invocations";
        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(tokenApiId)
                .resourceId(secureResourceId)
                .httpMethod("GET")
                .type(IntegrationType.AWS_PROXY)
                .integrationHttpMethod("POST")
                .uri(proxyUri)
                .build());

        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(tokenApiId)
                .description("token-auth-preservation")
                .build());
        gw.createStage(CreateStageRequest.builder()
                .restApiId(tokenApiId)
                .stageName("prod")
                .deploymentId(dep.id())
                .build());
    }

    /**
     * TOKEN authorizer event must contain exactly {@code type}, {@code methodArn},
     * and {@code authorizationToken} — no extra fields.
     */
    @Test
    @Order(12)
    void preservation_tokenAuthorizerEventShapeIsExact() throws Exception {
        String response = given()
                .header("Authorization", "Bearer mytoken")
                .when().get("/execute-api/" + tokenApiId + "/prod/secure")
                .then()
                .statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr, "TOKEN authorizer should embed receivedEvent in context");

        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);

        assertEquals("TOKEN", event.path("type").asText(null));
        assertFalse(event.path("methodArn").isMissingNode(), "methodArn must be present");
        assertFalse(event.path("methodArn").isNull(), "methodArn must not be null");
        assertEquals("Bearer mytoken", event.path("authorizationToken").asText(null));

        // TOKEN event must NOT contain REQUEST-specific fields
        assertTrue(event.path("headers").isMissingNode() || event.path("headers").isNull(),
                "TOKEN event must NOT contain headers");
        assertTrue(event.path("queryStringParameters").isMissingNode() || event.path("queryStringParameters").isNull(),
                "TOKEN event must NOT contain queryStringParameters");
        assertTrue(event.path("requestContext").isMissingNode() || event.path("requestContext").isNull(),
                "TOKEN event must NOT contain requestContext");
    }

    // ──────────────────────────── NONE authorizer preservation ────────────────────────────

    @Test
    @Order(20)
    void preservation_setupNoneAuthorizerApi() throws Exception {
        createNodeLambda(NONE_INTEGRATION_FUNCTION, """
                exports.handler = async (event) => ({
                  statusCode: 200,
                  body: JSON.stringify({ invoked: true })
                });
                """);

        var api = gw.createRestApi(CreateRestApiRequest.builder()
                .name("none-authorizer-preservation-api")
                .build());
        noneApiId = api.id();

        var resources = gw.getResources(GetResourcesRequest.builder()
                .restApiId(noneApiId)
                .build());
        String rootId = resources.items().get(0).id();

        var openRes = gw.createResource(CreateResourceRequest.builder()
                .restApiId(noneApiId)
                .parentId(rootId)
                .pathPart("open")
                .build());
        String openResourceId = openRes.id();

        gw.putMethod(PutMethodRequest.builder()
                .restApiId(noneApiId)
                .resourceId(openResourceId)
                .httpMethod("GET")
                .authorizationType("NONE")
                .build());

        String integrationUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + NONE_INTEGRATION_FUNCTION + "/invocations";
        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(noneApiId)
                .resourceId(openResourceId)
                .httpMethod("GET")
                .type(IntegrationType.AWS_PROXY)
                .integrationHttpMethod("POST")
                .uri(integrationUri)
                .build());

        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(noneApiId)
                .description("none-auth-preservation")
                .build());
        gw.createStage(CreateStageRequest.builder()
                .restApiId(noneApiId)
                .stageName("prod")
                .deploymentId(dep.id())
                .build());
    }

    @Test
    @Order(21)
    void preservation_noneAuthorizerSkipsInvocation() {
        given()
                .when().get("/execute-api/" + noneApiId + "/prod/open")
                .then()
                .statusCode(200)
                .body("invoked", org.hamcrest.Matchers.equalTo(true));
    }

    // ──────────────────────────── Allow / Deny policy preservation ────────────────────────────

    @Test
    @Order(30)
    void preservation_requestAuthorizerAllowPolicyForwardsToIntegration() {
        given()
                .header("Authorization", "Bearer test")
                .when().get("/execute-api/" + apiId + "/prod/items/42")
                .then()
                .statusCode(200);
    }

    @Test
    @Order(40)
    void preservation_setupDenyAuthorizerApi() throws Exception {
        createNodeLambda(DENY_AUTHORIZER_FUNCTION, """
                exports.handler = async (event) => ({
                  principalId: "test-user",
                  policyDocument: {
                    Version: "2012-10-17",
                    Statement: [{
                      Action: "execute-api:Invoke",
                      Effect: "Deny",
                      Resource: event.methodArn
                    }]
                  }
                });
                """);

        var api = gw.createRestApi(CreateRestApiRequest.builder()
                .name("deny-authorizer-preservation-api")
                .build());
        denyApiId = api.id();

        var resources = gw.getResources(GetResourcesRequest.builder()
                .restApiId(denyApiId)
                .build());
        String rootId = resources.items().get(0).id();

        var protectedRes = gw.createResource(CreateResourceRequest.builder()
                .restApiId(denyApiId)
                .parentId(rootId)
                .pathPart("protected")
                .build());
        String protectedResourceId = protectedRes.id();

        String authUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + DENY_AUTHORIZER_FUNCTION + "/invocations";
        var denyAuth = gw.createAuthorizer(CreateAuthorizerRequest.builder()
                .restApiId(denyApiId)
                .name("deny-authorizer")
                .type(AuthorizerType.REQUEST)
                .authorizerUri(authUri)
                .identitySource("method.request.header.Authorization")
                .authorizerResultTtlInSeconds(0)
                .build());

        gw.putMethod(PutMethodRequest.builder()
                .restApiId(denyApiId)
                .resourceId(protectedResourceId)
                .httpMethod("GET")
                .authorizationType("CUSTOM")
                .authorizerId(denyAuth.id())
                .build());

        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(denyApiId)
                .resourceId(protectedResourceId)
                .httpMethod("GET")
                .type(IntegrationType.MOCK)
                .requestTemplates(Map.of("application/json", "{\"statusCode\": 200}"))
                .build());

        // Method response and integration response for MOCK
        given()
                .contentType(ContentType.JSON)
                .body("{\"responseParameters\":{}}")
                .when().put("/restapis/" + denyApiId + "/resources/" + protectedResourceId + "/methods/GET/responses/200")
                .then()
                .statusCode(201);
        given()
                .contentType(ContentType.JSON)
                .body("{\"selectionPattern\":\"\",\"responseTemplates\":{\"application/json\":\"{\\\"message\\\":\\\"ok\\\"}\"}}")
                .when().put("/restapis/" + denyApiId + "/resources/" + protectedResourceId + "/methods/GET/integration/responses/200")
                .then()
                .statusCode(201);

        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(denyApiId)
                .description("deny-auth-preservation")
                .build());
        gw.createStage(CreateStageRequest.builder()
                .restApiId(denyApiId)
                .stageName("prod")
                .deploymentId(dep.id())
                .build());
    }

    @Test
    @Order(41)
    void preservation_requestAuthorizerDenyPolicyReturns403() {
        given()
                .header("Authorization", "Bearer anytoken")
                .when().get("/execute-api/" + denyApiId + "/prod/protected")
                .then()
                .statusCode(403);
    }

    // ──────────────────────────── Stage Variables ────────────────────────────

    /**
     * Validates that stageVariables in the REQUEST authorizer event and the proxy event
     * are populated from the Stage's variables map when variables are configured.
     */
    private String stageVarApiId;

    @Test
    @Order(50)
    void stageVariables_setupApiWithStageVars() throws Exception {
        createNodeLambda("apigw-stagevar-auth-echo", """
                exports.handler = async (event) => ({
                  principalId: "user",
                  policyDocument: {
                    Version: "2012-10-17",
                    Statement: [{ Action: "execute-api:Invoke", Effect: "Allow", Resource: event.methodArn }]
                  },
                  context: { receivedEvent: JSON.stringify(event) }
                });
                """);
        createNodeLambda("apigw-stagevar-proxy", """
                exports.handler = async (event) => ({
                  statusCode: 200,
                  body: JSON.stringify({
                    stageVariables: event.stageVariables,
                    authorizer: event.requestContext && event.requestContext.authorizer
                      ? event.requestContext.authorizer : null
                  })
                });
                """);

        var api = gw.createRestApi(CreateRestApiRequest.builder()
                .name("stage-var-test-api")
                .build());
        stageVarApiId = api.id();

        var resources = gw.getResources(GetResourcesRequest.builder().restApiId(stageVarApiId).build());
        String rootId = resources.items().get(0).id();

        var res = gw.createResource(CreateResourceRequest.builder()
                .restApiId(stageVarApiId).parentId(rootId).pathPart("ping").build());
        String resourceId = res.id();

        String authUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:apigw-stagevar-auth-echo/invocations";
        var auth = gw.createAuthorizer(CreateAuthorizerRequest.builder()
                .restApiId(stageVarApiId).name("sv-auth").type(AuthorizerType.REQUEST)
                .authorizerUri(authUri).identitySource("method.request.header.Authorization")
                .authorizerResultTtlInSeconds(0).build());

        gw.putMethod(PutMethodRequest.builder()
                .restApiId(stageVarApiId).resourceId(resourceId).httpMethod("GET")
                .authorizationType("CUSTOM").authorizerId(auth.id()).build());

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:apigw-stagevar-proxy/invocations";
        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(stageVarApiId).resourceId(resourceId).httpMethod("GET")
                .type(IntegrationType.AWS_PROXY).integrationHttpMethod("POST").uri(proxyUri).build());

        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(stageVarApiId).description("sv-test").build());
        // Create stage WITH variables
        gw.createStage(CreateStageRequest.builder()
                .restApiId(stageVarApiId).stageName("prod").deploymentId(dep.id())
                .variables(Map.of("env", "test", "version", "v1"))
                .build());
    }

    @Test
    @Order(51)
    void stageVariables_authorizerEventContainsStageVars() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .when().get("/execute-api/" + stageVarApiId + "/prod/ping")
                .then().statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);

        // Proxy event stageVariables
        JsonNode proxyStageVars = payload.path("stageVariables");
        assertFalse(proxyStageVars.isNull(), "proxy event stageVariables must be non-null");
        assertEquals("test", proxyStageVars.path("env").asText(null));
        assertEquals("v1", proxyStageVars.path("version").asText(null));

        // Authorizer event stageVariables (embedded in context)
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr);
        JsonNode authEvent = OBJECT_MAPPER.readTree(receivedEventStr);
        JsonNode authStageVars = authEvent.path("stageVariables");
        assertFalse(authStageVars.isNull(), "authorizer event stageVariables must be non-null");
        assertEquals("test", authStageVars.path("env").asText(null));
        assertEquals("v1", authStageVars.path("version").asText(null));
    }

    // ──────────────────────────── API Key Resolution ────────────────────────────

    /**
     * Validates that identity.apiKey is populated when a matching usage plan key
     * is linked to the (apiId, stage) pair and the x-api-key header matches.
     */
    private String apiKeyApiId;

    @Test
    @Order(60)
    void apiKey_setupApiWithUsagePlan() throws Exception {
        createNodeLambda("apigw-apikey-auth-echo", """
                exports.handler = async (event) => ({
                  principalId: "user",
                  policyDocument: {
                    Version: "2012-10-17",
                    Statement: [{ Action: "execute-api:Invoke", Effect: "Allow", Resource: event.methodArn }]
                  },
                  context: { receivedEvent: JSON.stringify(event) }
                });
                """);
        createNodeLambda("apigw-apikey-proxy", """
                exports.handler = async (event) => ({
                  statusCode: 200,
                  body: JSON.stringify({
                    authorizer: event.requestContext && event.requestContext.authorizer
                      ? event.requestContext.authorizer : null
                  })
                });
                """);

        var api = gw.createRestApi(CreateRestApiRequest.builder().name("apikey-test-api").build());
        apiKeyApiId = api.id();

        var resources = gw.getResources(GetResourcesRequest.builder().restApiId(apiKeyApiId).build());
        String rootId = resources.items().get(0).id();

        var res = gw.createResource(CreateResourceRequest.builder()
                .restApiId(apiKeyApiId).parentId(rootId).pathPart("secure").build());
        String resourceId = res.id();

        String authUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:apigw-apikey-auth-echo/invocations";
        var auth = gw.createAuthorizer(CreateAuthorizerRequest.builder()
                .restApiId(apiKeyApiId).name("ak-auth").type(AuthorizerType.REQUEST)
                .authorizerUri(authUri).identitySource("method.request.header.Authorization")
                .authorizerResultTtlInSeconds(0).build());

        gw.putMethod(PutMethodRequest.builder()
                .restApiId(apiKeyApiId).resourceId(resourceId).httpMethod("GET")
                .authorizationType("CUSTOM").authorizerId(auth.id()).build());

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:apigw-apikey-proxy/invocations";
        gw.putIntegration(PutIntegrationRequest.builder()
                .restApiId(apiKeyApiId).resourceId(resourceId).httpMethod("GET")
                .type(IntegrationType.AWS_PROXY).integrationHttpMethod("POST").uri(proxyUri).build());

        var dep = gw.createDeployment(CreateDeploymentRequest.builder()
                .restApiId(apiKeyApiId).description("ak-test").build());
        gw.createStage(CreateStageRequest.builder()
                .restApiId(apiKeyApiId).stageName("prod").deploymentId(dep.id()).build());

        // Create API key + usage plan linked to this (apiId, stage)
        given().contentType(ContentType.JSON)
                .body("{\"name\":\"test-key\",\"value\":\"my-secret-api-key\",\"enabled\":true}")
                .when().post("/apikeys")
                .then().statusCode(201);

        // Get the key ID
        String keyId = given().when().get("/apikeys")
                .then().statusCode(200)
                .extract().path("item.find { it.name == 'test-key' }.id");

        // Create usage plan linked to (apiKeyApiId, prod)
        String planId = given().contentType(ContentType.JSON)
                .body("""
                        {"name":"test-plan","apiStages":[{"apiId":"%s","stage":"prod"}]}
                        """.formatted(apiKeyApiId))
                .when().post("/usageplans")
                .then().statusCode(201)
                .extract().path("id");

        // Link the key to the plan
        given().contentType(ContentType.JSON)
                .body("{\"keyId\":\"%s\",\"keyType\":\"API_KEY\"}".formatted(keyId))
                .when().post("/usageplans/" + planId + "/keys")
                .then().statusCode(201);
    }

    @Test
    @Order(61)
    void apiKey_identityApiKeyPopulatedWhenHeaderMatches() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .header("x-api-key", "my-secret-api-key")
                .when().get("/execute-api/" + apiKeyApiId + "/prod/secure")
                .then().statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr);
        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);

        assertEquals("my-secret-api-key",
                event.path("requestContext").path("identity").path("apiKey").asText(null),
                "identity.apiKey must equal the matched usage plan key value");
    }

    @Test
    @Order(62)
    void apiKey_identityApiKeyNullWhenNoHeaderPresent() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .when().get("/execute-api/" + apiKeyApiId + "/prod/secure")
                .then().statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr);
        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);

        assertTrue(event.path("requestContext").path("identity").path("apiKey").isNull(),
                "identity.apiKey must be null when no x-api-key header is present");
    }

    @Test
    @Order(63)
    void apiKey_identityApiKeyNullWhenHeaderDoesNotMatchAnyPlanKey() throws Exception {
        String response = given()
                .header("Authorization", "Bearer test")
                .header("x-api-key", "wrong-key-value")
                .when().get("/execute-api/" + apiKeyApiId + "/prod/secure")
                .then().statusCode(200)
                .extract().asString();

        JsonNode payload = OBJECT_MAPPER.readTree(response);
        String receivedEventStr = payload.path("authorizer").path("receivedEvent").asText(null);
        assertNotNull(receivedEventStr);
        JsonNode event = OBJECT_MAPPER.readTree(receivedEventStr);

        assertTrue(event.path("requestContext").path("identity").path("apiKey").isNull(),
                "identity.apiKey must be null when x-api-key header does not match any plan key");
    }

    // ──────────────────────────── Cleanup ────────────────────────────

    @Test
    @Order(99)
    void cleanup() {
        if (apiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(apiId).build());
        }
        if (tokenApiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(tokenApiId).build());
        }
        if (noneApiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(noneApiId).build());
        }
        if (denyApiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(denyApiId).build());
        }
        if (stageVarApiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(stageVarApiId).build());
        }
        if (apiKeyApiId != null) {
            gw.deleteRestApi(DeleteRestApiRequest.builder().restApiId(apiKeyApiId).build());
        }
        deleteFunction(AUTHORIZER_FUNCTION);
        deleteFunction(PROXY_FUNCTION);
        deleteFunction(TOKEN_AUTHORIZER_FUNCTION);
        deleteFunction(TOKEN_PROXY_FUNCTION);
        deleteFunction(NONE_INTEGRATION_FUNCTION);
        deleteFunction(DENY_AUTHORIZER_FUNCTION);
        deleteFunction("apigw-stagevar-auth-echo");
        deleteFunction("apigw-stagevar-proxy");
        deleteFunction("apigw-apikey-auth-echo");
        deleteFunction("apigw-apikey-proxy");
    }

    // ──────────────────────────── Helpers ────────────────────────────

    private void createNodeLambda(String functionName, String handlerSource) throws Exception {
        String zipBase64 = Base64.getEncoder().encodeToString(zipEntries(Map.of(
                "index.js", handlerSource
        )));
        given()
                .contentType(ContentType.JSON)
                .body("""
                        {
                          "FunctionName": "%s",
                          "Runtime": "nodejs20.x",
                          "Role": "%s",
                          "Handler": "index.handler",
                          "Timeout": 30,
                          "Code": {"ZipFile": "%s"}
                        }
                        """.formatted(functionName, ROLE_ARN, zipBase64))
                .when().post(LAMBDA_BASE_PATH)
                .then()
                .statusCode(201);
    }

    private static byte[] zipEntries(Map<String, String> entries) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

    private void deleteFunction(String functionName) {
        int statusCode = given()
                .when().delete(LAMBDA_BASE_PATH + "/" + functionName)
                .then()
                .extract().statusCode();
        assertTrue(statusCode == 204 || statusCode == 404);
    }
}
