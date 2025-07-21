<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\TransaksiLangganan;
use App\Models\Subscription;
use App\Models\SubscriptionPlan;
use Illuminate\Support\Facades\Auth;
use Midtrans\Config;
use Midtrans\Snap;
use Carbon\Carbon;

class SubscriptionController extends Controller
{

    // Fungsi untuk menghasilkan Snap Token
    public function generateSnapToken(Request $request)
    {
        try {
            $user = Auth::user();

            if ($response = $this->getPendingTransaction($user->id)) return $response;
            if ($response = $this->getCanceledTransaction($user->id)) return $response;     

            $subscriptionPlan = SubscriptionPlan::first();
            if (!$subscriptionPlan) {
                return response()->json(['error' => 'Paket langganan tidak tersedia.'], 404);
            }
    
            Config::$serverKey = config('midtrans.serverKey');
            Config::$isProduction = false;
            Config::$isSanitized = true;
            Config::$is3ds = true;
    
            $params = [
                'transaction_details' => [
                    'order_id' => 'SUBS-' . time(),
                    'gross_amount' => $subscriptionPlan->price,
                ],
                'customer_details' => [
                    'first_name' => $user->name,
                    'email' => $user->email,
                ],
            ];
    
            $snapToken = Snap::getSnapToken($params);
    
            $transaction = TransaksiLangganan::create([
                'id_user' => $user->id,
                'snap_token' => $snapToken,
                'amount' => $subscriptionPlan->price,
                'expired_at' => now()->addMinutes(20),
            ]);
    
            return response()->json([
                'snap_token' => $snapToken,
                'transaction_id' => $transaction->id,
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Terjadi kesalahan server.'], 500);
        }
    }

    // Fungsi untuk memproses pembayaran
    public function processPayment(Request $request, $transactionId)
    {
        try {
            $transaction = TransaksiLangganan::findOrFail($transactionId);
            $paymentResult = $request->input('payment_result');
    
            if ($paymentResult['status_code'] == 200) {
                $subscriptionPlan = SubscriptionPlan::first();
    
                // Cek apakah user sudah memiliki langganan aktif
                $existingSubscription = Subscription::where('id_user', $transaction->id_user)
                    ->where('ends_at', '>=', now()) // Hanya langganan aktif
                    ->first();
    
                if ($existingSubscription) {
                    // Jika masih aktif, perpanjang durasi
                    $existingSubscription->update([
                        'ends_at' => $existingSubscription->ends_at->addDays($subscriptionPlan->duration),
                    ]);
                } else {
                    // Jika tidak aktif atau tidak ada, buat langganan baru
                    Subscription::create([
                        'id_user' => $transaction->id_user,
                        'started_at' => now(),
                        'ends_at' => now()->addDays($subscriptionPlan->duration),
                    ]);
                }
    
                // Update status transaksi
                $transaction->update([
                    'payment_method' => $paymentResult['payment_type'],
                    'status' => 'paid',
                ]);
    
                return response()->json(['success' => true]);
            }
    
            return response()->json(['success' => false, 'message' => 'Pembayaran gagal.'], 400);
        } catch (\Exception $e) {
            return response()->json(['success' => false, 'message' => 'Kesalahan server.'], 500);
        }
    }    
    
    protected function getPendingTransaction($userId)
    {
        $pendingTransaction = TransaksiLangganan::where('id_user', $userId)
            ->where('status', 'pending')
            ->where('expired_at', '>', now())
            ->first();

        return $pendingTransaction
            ? response()->json([
                'snap_token' => $pendingTransaction->snap_token,
                'transaction_id' => $pendingTransaction->id,
            ])
            : null;
    }

    protected function getCanceledTransaction($userId)
    {
        $canceledTransaction = TransaksiLangganan::where('id_user', $userId)
            ->where('status', 'canceled')
            ->where('expired_at', '>', now())
            ->first();
    
        return $canceledTransaction
            ? response()->json([
                'error' => "Anda memiliki transaksi sebelumnya yang dibatalkan. Tunggu hingga pukul {$canceledTransaction->expired_at->format('H:i:s')} sebelum mencoba kembali.",
            ], 403)
            : null;
    }
    
    public function cancelTransaction($transactionId)
    {
        try {
            $transaction = TransaksiLangganan::findOrFail($transactionId);
            $transaction->update(['status' => 'canceled']);
    
            return response()->json(['success' => true, 'message' => 'Transaksi berhasil dibatalkan.']);
        } catch (\Exception $e) {
            return response()->json(['success' => false, 'message' => 'Gagal membatalkan transaksi.'], 500);
        }
    }

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $subscriptions = Subscription::with('user')
            ->where('ends_at', '>', now())
            ->paginate(10);
    
        // Tambahkan atribut `remaining_time` dengan memanggil fungsi model
        foreach ($subscriptions as $subscription) {
            $subscription->remaining_time = $subscription->remainingPremiumTime();
        }
    
        return view('Admin/data_subscription', [
            "title" => "Data Subscription Aktif",
            "subscriptions" => $subscriptions,
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
