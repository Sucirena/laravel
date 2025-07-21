<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\TransaksiLangganan;

class ExpireTransactions extends Command
{
    // Nama dan deskripsi command
    protected $signature = 'transactions:expire';
    protected $description = 'Set expired status for transactions past their expired_at time';

    public function handle()
    {
        // Ambil transaksi yang sudah melewati waktu expired dan masih berstatus 'pending'
        $expiredTransactions = TransaksiLangganan::where('status', 'pending')
            ->where('expired_at', '<', now())
            ->get();

        foreach ($expiredTransactions as $transaction) {
            $transaction->update(['status' => 'expired']);
        }

        // Informasi di terminal saat schedule dijalankan
        $this->info('Expired transactions have been updated.');
    }
}
