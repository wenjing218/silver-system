//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

//
// TODO auto-generated type
//
simple Server
{
    @display("i=old/server1");

    gates:
        input in;
        output out;
}

simple Car
{
    gates:
        input in;
        output out;
}

network kyber512aes128
{
    @display("bgb=1163.62,325.58");
    submodules:
        car: Car {  // the limit parameter is still unbound here. We will get it from the ini file
            @display("p=129.94,148.92");
        }
        server: Server {
            @display("p=1007.39996,148.92");
        }
    connections:
        server.out --> {  delay = 10s; } --> car.in;
        server.in <-- {  delay = 10s; } <-- car.out;
}
