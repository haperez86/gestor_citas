<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

class JwtMiddleware
{
    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Token no proporcionado'], 401);
        }

        try {
            $key = env('JWT_SECRET');
            $decoded = JWT::decode($token, new Key($key, 'HS256'));

            // Asegúrate de que el campo `sub` del token contiene el ID del usuario
            $request->attributes->set('user_id', $decoded->sub);

        } catch (\Firebase\JWT\ExpiredException $e) {
            return response()->json(['error' => 'El token ha expirado'], 401);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            return response()->json(['error' => 'La firma del token es inválida'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token inválido o no procesable'], 401);
        }

        return $next($request);
    }
}
