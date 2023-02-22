<?php
namespace DMT\Test\Http\AntiXss\Middleware;

use DMT\Http\AntiXss\Middleware\AntiXssMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AntiXssMiddlewareTest extends TestCase
{
    public function testAntiXssPost()
    {
        $request = $this->getMockForAbstractClass(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn([
            'xss' => "<script>alert('xss')</script>",
        ]);

        $endpoint = $this->getMockForAbstractClass(RequestHandlerInterface::class);
        $endpoint->expects($this->never())->method('handle');


        $middleware = new AntiXssMiddleware(new HttpFactory());

        $response = $middleware->process($request, $endpoint);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('400 Bad Request', $response->getReasonPhrase());
    }

    public function testAntiXssPostOk()
    {
        $request = $this->getMockForAbstractClass(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn([
            'no-xss' => "this is ok"
        ]);

        $endpoint = $this->getMockForAbstractClass(RequestHandlerInterface::class);
        $endpoint->expects($this->once())->method('handle')->willReturn(new Response(200));


        $middleware = new AntiXssMiddleware(new HttpFactory());

        $response = $middleware->process($request, $endpoint);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testAntiXssQueryParams()
    {
        $request = $this->getMockForAbstractClass(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getQueryParams')->willReturn([
            'xss' => "<script>alert('xss')</script>",
        ]);

        $endpoint = $this->getMockForAbstractClass(RequestHandlerInterface::class);
        $endpoint->expects($this->never())->method('handle');

        $middleware = new AntiXssMiddleware(new HttpFactory());

        $response = $middleware->process($request, $endpoint);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('400 Bad Request', $response->getReasonPhrase());
    }
}
