<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

class JwtAuthMiddleware
{
    private $key = 'PASSWORD_DE_MI_APLICACION'; // Usa tu clave secreta

    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Token no proporcionado'], 401);
        }

        try {
            //$decoded = JWT::decode($token, new Key($this->key, 'HS256'));
            $key = env('JWT_SECRET');
            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            
            //$request->attributes->set('user_id', $decoded->sub); // Añade el user_id al request
            $request->user = \App\Models\User::find($decoded->sub);
        } catch (\Firebase\JWT\ExpiredException $e) {
            return response()->json(['error' => 'El token ha expirado'], 401);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            return response()->json(['error' => 'Firma de token inválida'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token inválido'], 401);
        }

        return $next($request);
    }
}
