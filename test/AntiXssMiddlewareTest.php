<?php
namespace DMT\Http\AntiXss\Middleware;

use GuzzleHttp\Psr7\Response;
use HttpException\BadRequestException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AntiXssMiddlewareTest extends TestCase
{
    public function testAntiXssPost()
    {
        $this->expectException(BadRequestException::class);

        $request = $this->getMockForAbstractClass(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn([
            'xss' => "<script>alert('xss')</script>",
        ]);

        $endpoint = $this->getMockForAbstractClass(RequestHandlerInterface::class);
        $endpoint->expects($this->never())->method('handle');


        $middleware = new AntiXssMiddleware();

        $middleware->process($request, $endpoint);
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


        $middleware = new AntiXssMiddleware();

        $middleware->process($request, $endpoint);
    }

}
