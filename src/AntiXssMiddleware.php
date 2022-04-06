<?php

namespace DMT\Http\AntiXss\Middleware;

use HttpException\BadRequestException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use voku\helper\AntiXSS;

/**
 * Class AntiXssMiddleware
 */
class AntiXssMiddleware implements MiddlewareInterface
{
    protected AntiXSS $antiXss;
    protected array $methods;

    public function __construct(AntiXSS $antiXSS = null, array $methods = ['post', 'put', 'path'])
    {
        $this->antiXss = $antiXSS ?? new AntiXSS();
        $this->methods = array_map('strtoupper', $methods);
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array(strtoupper($request->getMethod()), $this->methods)) {
            $this->xssCheck($request);
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws BadRequestException
     */
    protected function xssCheck(ServerRequestInterface $request): void
    {
        $this->antiXss->xss_clean($request->getParsedBody());

        if ($this->antiXss->isXssFound()) {
            throw new BadRequestException();
        }
    }
}
