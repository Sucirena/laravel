<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('subscription_plan', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap subscription plan
            $table->string('name', 50); // Nama rencana (monthly, yearly)
            $table->decimal('price', 10, 2); // Total biaya rencana subscription (disesuaikan ukuran kolom agar sama dengan transaksi_konsultasi)
            $table->integer('duration'); // Durasi dalam hari (misal 30 hari atau 365 hari)
            $table->timestamps(); // Timestamps created_at dan updated_at
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('subscription_plan');
    }
};
