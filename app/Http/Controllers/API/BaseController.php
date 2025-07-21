<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\JsonResponse;
use App\Http\Controllers\Controller;

class BaseController extends Controller
{
    /**
     * Success response method.
     */
    public function sendResponse($result, $message): JsonResponse
    {
        return response()->json([
            'success' => true,
            'data'    => $result,
            'message' => $message,
        ], 200);
    }

    /**
     * Return error response.
     */
    public function sendError($error, $errorMessages = [], $code = 404): JsonResponse
    {
        $response = [
            'success' => false,
            'message' => $error,
        ];

        if (!empty($errorMessages)) {
            $response['data'] = $errorMessages;
        }

        return response()->json($response, $code);
    }
}
