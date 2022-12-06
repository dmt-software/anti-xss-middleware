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

    public function __construct(AntiXSS $antiXSS = null, array $methods = ['get', 'post', 'put', 'patch'])
    {
        $this->antiXss = $antiXSS ?? new AntiXSS();
        $this->methods = array_map('strtoupper', $methods);
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws BadRequestException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array(strtoupper($request->getMethod()), $this->methods)) {
            $this->xssCheckQueryParams($request);
            $this->xssCheckBody($request);
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws BadRequestException
     */
    protected function xssCheckBody(ServerRequestInterface $request): void
    {
        $parsedBody = $request->getParsedBody();

        if (is_null($parsedBody)) {
            return;
        }

        if (is_string($parsedBody) || is_array($parsedBody)) {
            $this->antiXss->xss_clean($parsedBody);
        }

        if (is_object($parsedBody)) {
            $this->antiXss->xss_clean(get_object_vars($parsedBody));
        }

        if ($this->antiXss->isXssFound()) {
            throw new BadRequestException();
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @return void
     * @throws BadRequestException
     */
    public function xssCheckQueryParams(ServerRequestInterface $request): void
    {
        $params = $request->getQueryParams();

        if (!$params) {
            return;
        }

        $this->antiXss->xss_clean($params);

        if ($this->antiXss->isXssFound()) {
            throw new BadRequestException();
        }
    }
}
