# Anti XSS Middleware

This middleware implements the PSR-15 MiddlewareInterface and can be helpful to prevent XSS attacks. 

## Installation

```bash
composer install dmt-software/anti-xss-middleware
```

## Usage

```php
use DMT\Http\AntiXss\Middleware\AntiXssMiddleware;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** @var ResponseFactoryInterface $responseFactory */
$antiXssMiddleware = new AntiXssMiddleware($responseFactory);

/** @var ServerRequestInterface $request */
/** @var RequestHandlerInterface $handler */
$response = $antiXssMiddleware->process($request, $handler);

if ($response->getStatusCode() === 400) {
    // cross site scripting detected
}
```
